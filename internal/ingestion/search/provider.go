// Package search implements a targeted/org-scoped ingestion provider for séance
// built on GitHub's commit Search API (GET /search/commits). Where the events
// provider listens to the global firehose of fresh pushes, this provider polls
// the *indexed* search corpus for operator-supplied keywords — "watch for
// `acme-corp`" — and catches leaks the events stream misses: indexed files in
// repos that were pushed before séance started, forks, and commits whose push
// event scrolled off the bounded events window.
//
// It is a complementary coverage axis, not a replacement: the global events
// stream remains séance's v0.1 thesis. The ingestion.Provider interface was
// explicitly designed for providers that "only support targeted repository
// scanning" — this is that sanctioned extension point.
//
// Rate-limit budget (the dominant design constraint):
//
//	The Search API has its OWN, much stricter quota than the core API:
//	30 requests/minute for authenticated callers, 10/minute unauthenticated.
//	A single poll issues one request per watched keyword, so the provider
//	governs its cadence against this separate ceiling — it never assumes the
//	5,000 req/hr core budget. The adaptive governor backs off when
//	X-RateLimit-Remaining runs low and recovers automatically on reset, mirroring
//	the events provider's two-way cadence (one-way backoff is not acceptable).
//
// This provider does NOT fetch file content — that is the Fetcher's job. Emitted
// CommitEvents have FilesKnown=false, so the downstream pipeline discovers the
// changed files via the same FetchAll path the events provider's new-format
// commits use. Prefilter, fetch, scan, dedup, and sinks are all reused unchanged.
package search

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

const (
	defaultBaseURL = "https://api.github.com"
	searchPath     = "/search/commits"
	userAgent      = "seance/0.1 (+https://github.com/bugsyhewitt/seance)"

	// The Search API's authenticated quota is 30 req/min. We poll conservatively
	// at this interval by default so a multi-keyword watch list stays well inside
	// the minute window: at 90s, even 10 keywords cost 10 req per ~1.5 min.
	defaultPollInterval = 90 * time.Second

	// When remaining search budget drops to this many requests or fewer, the
	// provider backs off to LowBudgetInterval until the window resets. The Search
	// API quota is small, so the floor is an absolute count, not a percentage.
	lowBudgetFloor = 3
)

// Metrics holds live instrumentation counters. All fields are updated atomically.
type Metrics struct {
	SearchRequests     uint64 // total GET /search/commits requests issued
	ResultsReceived    uint64 // total commit results parsed from API responses
	CommitsEmitted     uint64 // total CommitEvents sent downstream (post-dedup)
	RateLimitRemaining int64  // last observed X-RateLimit-Remaining (-1 = unknown)
	RateLimitReset     int64  // last observed X-RateLimit-Reset (Unix timestamp)
}

// Provider polls the GitHub commit Search API for operator keywords.
type Provider struct {
	token    string
	baseURL  string
	keywords []string

	// PollInterval is the normal cadence between full sweeps of the keyword list.
	// Defaults to defaultPollInterval; tunable for tests.
	PollInterval time.Duration
	// LowBudgetInterval is the backoff cadence used when the (stricter) Search-API
	// budget runs low. Defaults to 2 minutes.
	LowBudgetInterval time.Duration
	// PerPage caps results requested per keyword per poll. The Search API allows
	// up to 100; séance keeps it modest so a single noisy keyword cannot dominate
	// the budget or flood the pipeline. Defaults to 30.
	PerPage int

	client  *http.Client
	Metrics Metrics

	// seen bounds re-emission within a process: the Search index returns the same
	// top results every poll until something newer ranks higher, so without this
	// the provider would re-emit the same commits indefinitely. Cross-RUN dedup is
	// the pipeline's job (state.SeenCommits); this is only intra-run de-dup so the
	// channel isn't spammed between polls. It is intentionally unbounded-but-small:
	// a watch list surfaces a bounded set of repos, and the process-level seen set
	// is the same shape the events provider relies on downstream.
	seen map[string]struct{}
}

// New returns a search provider watching the given keywords. token may be empty
// for unauthenticated access (10 req/min — barely viable; a token is strongly
// recommended). Empty or whitespace-only keywords are ignored.
func New(token string, keywords ...string) *Provider {
	return NewWithBaseURL(token, defaultBaseURL, keywords...)
}

// NewWithBaseURL returns a search provider with a custom base URL (used in tests).
func NewWithBaseURL(token, baseURL string, keywords ...string) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	kw := make([]string, 0, len(keywords))
	for _, k := range keywords {
		if t := trimSpace(k); t != "" {
			kw = append(kw, t)
		}
	}
	p := &Provider{
		token:             token,
		baseURL:           baseURL,
		keywords:          kw,
		PollInterval:      defaultPollInterval,
		LowBudgetInterval: 2 * time.Minute,
		PerPage:           30,
		client:            &http.Client{Timeout: 30 * time.Second},
		seen:              make(map[string]struct{}),
	}
	p.Metrics.RateLimitRemaining = -1
	return p
}

// Keywords returns the (cleaned) keyword list this provider watches.
func (p *Provider) Keywords() []string { return p.keywords }

// Name implements ingestion.Provider.
func (p *Provider) Name() string { return "search" }

// Stream implements ingestion.Provider. Sweeps the keyword list at an adaptive
// interval governed by the Search API's own (stricter) rate-limit headers.
// With no keywords configured, Stream emits nothing and exits cleanly — the
// provider is inert rather than an error so it can be wired unconditionally.
func (p *Provider) Stream(ctx context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
	events := make(chan ingestion.CommitEvent, 64)
	errs := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errs)
		if len(p.keywords) == 0 {
			return
		}
		p.poll(ctx, events, errs)
	}()
	return events, errs
}

func (p *Provider) poll(ctx context.Context, events chan<- ingestion.CommitEvent, errs chan<- error) {
	ticker := time.NewTicker(p.PollInterval)
	defer ticker.Stop()
	var inBackoff bool

	for {
		for _, kw := range p.keywords {
			if err := p.sweep(ctx, kw, events); err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case errs <- err:
				default:
				}
				return
			}
			if ctx.Err() != nil {
				return
			}
		}

		// Recompute cadence against the Search API's own budget after each full
		// sweep. Two-way: back off when low, resume the moment the window resets.
		interval := p.PollInterval
		remaining := atomic.LoadInt64(&p.Metrics.RateLimitRemaining)
		lowBudget := remaining >= 0 && remaining <= lowBudgetFloor
		if lowBudget {
			if !inBackoff {
				fmt.Fprintf(os.Stderr, "séance[search]: search-api budget low (%d remaining) — backing off to %s\n", remaining, p.LowBudgetInterval)
				inBackoff = true
			}
			interval = p.LowBudgetInterval
		} else if inBackoff {
			fmt.Fprintf(os.Stderr, "séance[search]: search-api budget recovered (%d remaining) — resuming normal cadence\n", remaining)
			inBackoff = false
		}
		ticker.Reset(interval)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep issues one Search API request for a single keyword and emits an event
// for each not-yet-seen commit result.
func (p *Provider) sweep(ctx context.Context, keyword string, events chan<- ingestion.CommitEvent) error {
	q := url.Values{}
	q.Set("q", keyword)
	q.Set("sort", "committer-date")
	q.Set("order", "desc")
	q.Set("per_page", strconv.Itoa(p.PerPage))
	reqURL := p.baseURL + searchPath + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	// The commit search API requires the cloak-preview media type historically;
	// the modern endpoint accepts the standard media type. Send the standard one.
	req.Header.Set("Accept", "application/vnd.github+json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}

	atomic.AddUint64(&p.Metrics.SearchRequests, 1)

	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()

	p.updateRateLimit(resp)

	// 403 with remaining=0 is the secondary-rate-limit / abuse signal; surface it
	// as an error so the operator sees it, but the governor will already have
	// recorded the low remaining for the backoff decision.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github search (%q): HTTP %d", keyword, resp.StatusCode)
	}

	var body struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			SHA    string `json:"sha"`
			Commit struct {
				Message string `json:"message"`
				Author  struct {
					Name  string    `json:"name"`
					Email string    `json:"email"`
					Date  time.Time `json:"date"`
				} `json:"author"`
			} `json:"commit"`
			Repository struct {
				Name  string `json:"name"`
				Owner struct {
					Login string `json:"login"`
				} `json:"owner"`
			} `json:"repository"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("github search (%q): decode: %w", keyword, err)
	}

	for _, it := range body.Items {
		atomic.AddUint64(&p.Metrics.ResultsReceived, 1)
		if it.SHA == "" || it.Repository.Owner.Login == "" || it.Repository.Name == "" {
			continue
		}
		if _, ok := p.seen[it.SHA]; ok {
			continue // already emitted this run; cross-run dedup is the pipeline's job
		}
		p.seen[it.SHA] = struct{}{}

		select {
		case <-ctx.Done():
			return nil
		case events <- ingestion.CommitEvent{
			Provider:    "search",
			RepoOwner:   it.Repository.Owner.Login,
			RepoName:    it.Repository.Name,
			CommitSHA:   it.SHA,
			CommitMsg:   it.Commit.Message,
			AuthorName:  it.Commit.Author.Name,
			AuthorEmail: it.Commit.Author.Email,
			FilesKnown:  false, // fetcher discovers files via FetchAll, same as events new-format
			Timestamp:   it.Commit.Author.Date,
		}:
			atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
		}
	}
	return nil
}

func (p *Provider) updateRateLimit(resp *http.Response) {
	if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			atomic.StoreInt64(&p.Metrics.RateLimitRemaining, n)
		}
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			atomic.StoreInt64(&p.Metrics.RateLimitReset, n)
		}
	}
}

// trimSpace trims ASCII whitespace from both ends without pulling in strings
// (keeps the import set minimal and the behavior explicit for keyword cleaning).
func trimSpace(s string) string {
	start := 0
	for start < len(s) && isSpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
