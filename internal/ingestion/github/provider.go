// Package github implements the GitHub public events API provider for séance.
// It polls GET /events at the interval specified by X-Poll-Interval, caches
// ETags for conditional requests, and emits CommitEvents for PushEvents only.
//
// Rate-limit budget (single token, authenticated):
//   - 60 polls/hour @ 60s interval  =    60 requests
//   - ~900 surviving commits/hour   =   900 fetches  (post-prefilter)
//   - Total                         =   960 req/hr   (~19% of 5,000 ceiling)
//
// The actual throughput depends on live push volume and pre-filter survival
// rate, both of which are measured at runtime via the Metrics counter.
// Coverage is a bounded, delayed subset of public push activity — bounded
// by the events endpoint's pagination depth (max ~300 events per poll window).
// Exact fraction of total GitHub push activity is unknown.
//
// This provider does NOT fetch file content — that is the Fetcher's job.
// Pre-filtering happens downstream in the prefilter package.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

const (
	defaultPollInterval = 60 // seconds; overridden by X-Poll-Interval header
	defaultBaseURL      = "https://api.github.com"
	eventsPath          = "/events"
	userAgent           = "seance/0.1 (+https://github.com/bugsyhewitt/seance)"
	rateLimitSafetyPct  = 10 // widen poll interval when remaining < 10% of limit
)

// Metrics holds live instrumentation counters. All fields are updated atomically.
type Metrics struct {
	PushEventsReceived  uint64 // total PushEvents parsed from API responses
	CommitsEmitted      uint64 // total CommitEvents sent downstream
	ForcePushesReceived uint64 // total force-push events detected and emitted
	FetchRequests       uint64 // total HTTP GET /events requests issued
	RateLimitRemaining  int64  // last observed X-RateLimit-Remaining (-1 = unknown)
	RateLimitReset      int64  // last observed X-RateLimit-Reset (Unix timestamp)
}

// Provider polls the GitHub public events API and emits PushEvent commits.
type Provider struct {
	token             string
	baseURL           string
	pollInterval      int           // seconds; updated from X-Poll-Interval header
	LowBudgetInterval time.Duration // how long to back off when rate limit is low; default 5m
	// DetectForcePush controls whether force-push (history-rewrite) events are
	// emitted as ForcePush-flagged CommitEvents. Default true. Gated by the
	// --force-push CLI flag so operators can disable the extra compare-API cost.
	DetectForcePush bool
	client          *http.Client
	Metrics         Metrics
}

// New returns a GitHub provider. token may be empty for unauthenticated
// access (rate limit: 60 req/hr — not viable for production use).
func New(token string) *Provider {
	return NewWithBaseURL(token, defaultBaseURL)
}

// NewWithBaseURL returns a provider with a custom base URL (used in tests).
func NewWithBaseURL(token, baseURL string) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	p := &Provider{
		token:             token,
		baseURL:           baseURL,
		pollInterval:      defaultPollInterval,
		LowBudgetInterval: 5 * time.Minute,
		DetectForcePush:   true,
		client:            &http.Client{Timeout: 30 * time.Second},
	}
	p.Metrics.RateLimitRemaining = -1
	return p
}

// Name implements ingestion.Provider.
func (p *Provider) Name() string { return "github" }

// Stream implements ingestion.Provider. Polls the GitHub events endpoint
// at an adaptive interval driven by X-Poll-Interval and X-RateLimit-* headers.
func (p *Provider) Stream(ctx context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
	events := make(chan ingestion.CommitEvent, 64)
	errs := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errs)
		p.poll(ctx, events, errs)
	}()
	return events, errs
}

func (p *Provider) poll(ctx context.Context, events chan<- ingestion.CommitEvent, errs chan<- error) {
	var etag string
	var inBackoff bool
	ticker := time.NewTicker(time.Duration(p.pollInterval) * time.Second)
	defer ticker.Stop()

	for {
		if err := p.fetch(ctx, &etag, events); err != nil {
			select {
			case errs <- err:
			default:
			}
			return
		}

		// Recompute interval after each poll based on live rate-limit state.
		// Runs every loop so recovery is automatic: once the window resets and
		// X-RateLimit-Remaining is healthy again, normal cadence resumes.
		interval := time.Duration(p.pollInterval) * time.Second
		remaining := atomic.LoadInt64(&p.Metrics.RateLimitRemaining)
		lowBudget := remaining >= 0 && remaining < int64(p.pollInterval*rateLimitSafetyPct/100)
		if lowBudget {
			if !inBackoff {
				fmt.Fprintf(os.Stderr, "séance: rate-limit budget low (%d remaining) — backing off to %s poll\n", remaining, p.LowBudgetInterval)
				inBackoff = true
			}
			interval = p.LowBudgetInterval
		} else if inBackoff {
			fmt.Fprintf(os.Stderr, "séance: rate-limit budget recovered (%d remaining) — resuming normal cadence\n", remaining)
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

func (p *Provider) fetch(ctx context.Context, etag *string, events chan<- ingestion.CommitEvent) error {
	url := p.baseURL + eventsPath
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	if *etag != "" {
		req.Header.Set("If-None-Match", *etag)
	}

	atomic.AddUint64(&p.Metrics.FetchRequests, 1)

	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil // context cancelled — not an error
		}
		return err
	}
	defer resp.Body.Close()

	// Update adaptive poll interval from server hint.
	if v := resp.Header.Get("X-Poll-Interval"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			p.pollInterval = secs
		}
	}

	// Update rate-limit state for adaptive cadence decisions.
	p.updateRateLimit(resp)

	if resp.StatusCode == http.StatusNotModified {
		return nil // no new events
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github events: HTTP %d", resp.StatusCode)
	}

	if newETag := resp.Header.Get("ETag"); newETag != "" {
		*etag = newETag
	}

	var rawEvents []struct {
		ID        string                 `json:"id"`
		Type      string                 `json:"type"`
		Actor     struct{ Login string } `json:"actor"`
		Repo      struct{ Name string }  `json:"repo"`
		Payload   json.RawMessage        `json:"payload"`
		CreatedAt time.Time              `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawEvents); err != nil {
		return fmt.Errorf("github events: decode: %w", err)
	}

	for _, ev := range rawEvents {
		if ev.Type != "PushEvent" {
			continue
		}
		atomic.AddUint64(&p.Metrics.PushEventsReceived, 1)
		p.parsePushEvent(ev.Actor.Login, ev.Repo.Name, ev.CreatedAt, ev.Payload, events)
	}
	return nil
}

func (p *Provider) parsePushEvent(actor, repoFull string, ts time.Time, payload json.RawMessage, events chan<- ingestion.CommitEvent) {
	// Parse both the legacy format (commits array with file lists) and the
	// current GitHub API format (head/before/ref only, no commits array).
	var push struct {
		Head         string `json:"head"`
		Before       string `json:"before"`
		Ref          string `json:"ref"`
		Forced       bool   `json:"forced"`
		Size         int    `json:"size"`
		DistinctSize int    `json:"distinct_size"`
		Commits      []struct {
			SHA     string `json:"sha"`
			Message string `json:"message"`
			Author  struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"author"`
			Added    []string `json:"added"`
			Modified []string `json:"modified"`
			Removed  []string `json:"removed"`
		} `json:"commits"`
	}
	if err := json.Unmarshal(payload, &push); err != nil {
		return
	}

	owner, name := splitRepo(repoFull)

	if len(push.Commits) > 0 {
		// Legacy format: commits and file paths present in the event payload.
		for _, c := range push.Commits {
			var files []ingestion.FileRef
			for _, f := range c.Added {
				files = append(files, ingestion.FileRef{Path: f, Status: "added"})
			}
			for _, f := range c.Modified {
				files = append(files, ingestion.FileRef{Path: f, Status: "modified"})
			}
			for _, f := range c.Removed {
				files = append(files, ingestion.FileRef{Path: f, Status: "removed"})
			}
			events <- ingestion.CommitEvent{
				Provider:    "github",
				RepoOwner:   owner,
				RepoName:    name,
				CommitSHA:   c.SHA,
				CommitMsg:   c.Message,
				AuthorName:  c.Author.Name,
				AuthorEmail: c.Author.Email,
				Files:       files,
				FilesKnown:  true,
				Timestamp:   ts,
			}
			atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
		}
		return
	}

	// Detect a force-push (history rewrite). The before SHA points at the tip
	// that became dangling — that is where a panic-deleted secret lives. We emit
	// a ForcePush-flagged event carrying the before SHA so the fetcher can compare
	// before...head and recover the orphaned diff. Branch creations (before is the
	// zero SHA) and branch deletions (head is the zero SHA) have no recoverable
	// prior tip, so they are excluded.
	if p.DetectForcePush && isForcePush(push.Forced, push.DistinctSize, push.Before, push.Head) {
		events <- ingestion.CommitEvent{
			Provider:   "github",
			RepoOwner:  owner,
			RepoName:   name,
			CommitSHA:  push.Head,
			AuthorName: actor,
			FilesKnown: false,
			ForcePush:  true,
			BeforeSHA:  push.Before,
			Timestamp:  ts,
		}
		atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
		atomic.AddUint64(&p.Metrics.ForcePushesReceived, 1)
		return
	}

	// New API format (GitHub removed commits from payload): use the head SHA.
	// File paths are not known — the fetcher will discover them.
	if push.Head != "" {
		events <- ingestion.CommitEvent{
			Provider:   "github",
			RepoOwner:  owner,
			RepoName:   name,
			CommitSHA:  push.Head,
			AuthorName: actor, // only the actor (pusher login) is available
			FilesKnown: false,
			Timestamp:  ts,
		}
		atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
	}
}

// zeroSHA is the all-zero object name GitHub uses for branch creation (as
// "before") and branch deletion (as "head").
const zeroSHA = "0000000000000000000000000000000000000000"

// isForcePush reports whether a push payload has the force-push (history-rewrite)
// shape: HEAD moved off a real prior tip that is now dangling. This is true when
// the payload's forced flag is set, or when HEAD changed (before != head) with no
// distinct commits — meaning HEAD was reset backward rather than advanced. Branch
// creations (before == zero) and deletions (head == zero) are excluded because
// there is no recoverable orphaned tip.
func isForcePush(forced bool, distinctSize int, before, head string) bool {
	if before == "" || head == "" || before == head {
		return false
	}
	if before == zeroSHA || head == zeroSHA {
		return false
	}
	return forced || distinctSize == 0
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

func splitRepo(full string) (owner, name string) {
	for i, c := range full {
		if c == '/' {
			return full[:i], full[i+1:]
		}
	}
	return full, ""
}
