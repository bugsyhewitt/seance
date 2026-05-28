package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bugsyhewitt/seance/internal/fetch"
	ghprovider "github.com/bugsyhewitt/seance/internal/ingestion/github"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/output/ndjson"
	"github.com/bugsyhewitt/seance/internal/output/tui"
	"github.com/bugsyhewitt/seance/internal/output/webhook"
	"github.com/bugsyhewitt/seance/internal/prefilter"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
	"github.com/bugsyhewitt/seance/internal/state"
	"github.com/bugsyhewitt/seance/pkg/config"
)

func runPipeline(ctx context.Context, c config.Config) error {
	rs, err := ruleset.LoadFile(c.SignaturesPath)
	if err != nil {
		return fmt.Errorf("load signatures: %w", err)
	}
	fmt.Fprintf(os.Stderr, "séance: loaded %d rules from %s\n", len(rs.Rules), c.SignaturesPath)

	store := state.NewJSONFileStorage(filepath.Join(c.StateDir, "state.json"))
	st, err := store.Load()
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	// seenTTL bounds the SeenCommits map so state size does not grow unbounded
	// for the life of the process. Defaults to 7 days via config.SeenTTLDays.
	seenTTL := time.Duration(c.SeenTTLDays) * 24 * time.Hour

	// stMu guards all access to st.SeenCommits, which is mutated by the main
	// loop and read/trimmed by the metrics and eviction goroutines.
	var stMu sync.Mutex

	defer func() {
		// Evict stale seen-commit entries before the final persist so the
		// on-disk state file stays bounded across restarts.
		stMu.Lock()
		st.Evict(seenTTL)
		st.LastUpdated = time.Now()
		stMu.Unlock()
		_ = store.Save(st)
	}()

	// The primary stdout sink is either the live TUI feed (--tui on an interactive
	// terminal) or the raw NDJSON stream. --tui degrades to NDJSON automatically
	// when stdout is not a TTY (a pipe, a file, CI) so a redirected stream is never
	// corrupted by escape sequences. Either way it is just one output.Sink; the
	// scan/dedup/alerting data path is identical. Additional sinks (webhook) fan
	// out from the same Scan via the variadic engine constructor.
	primary := primaryStdoutSink(c)
	sinks := []output.Sink{primary}

	// Optional webhook alerting sink. Constructed only when a URL is configured.
	// Its Close (drain + flush) runs after the stdout sink's, both via defers.
	var webhookSink *webhook.Sink
	if c.WebhookURL != "" {
		headers, herr := parseWebhookHeaders(c.WebhookHeaders)
		if herr != nil {
			return fmt.Errorf("webhook header: %w", herr)
		}
		webhookSink = webhook.New(webhook.Config{
			URL:           c.WebhookURL,
			Headers:       headers,
			MinConfidence: c.WebhookMinConfidence,
			ErrLog:        os.Stderr,
		})
		sinks = append(sinks, webhookSink)
		fmt.Fprintf(os.Stderr, "séance: webhook alerting enabled — POSTing findings (confidence >= %.2f) to %s\n",
			c.WebhookMinConfidence, c.WebhookURL)
	}
	for _, s := range sinks {
		defer s.Close()
	}

	engine := scan.New(rs.Rules, sinks...)

	// Cross-run finding deduplication / re-leak suppression. The suppressor is
	// backed by the persisted SeenFindings set (so a secret re-pushed or forked
	// after a restart is alerted once, not every run) plus an optional operator
	// suppress-list loaded from --suppress-file. It shares stMu with every other
	// State reader so its bookkeeping cannot race eviction or the final persist.
	suppressList, serr := loadSuppressFile(c.SuppressFile)
	if serr != nil {
		return fmt.Errorf("suppress file: %w", serr)
	}
	engine.WithSuppressor(state.NewFindingSuppressor(&stMu, st, suppressList))
	if c.SuppressFile != "" {
		fmt.Fprintf(os.Stderr, "séance: loaded %d suppress-list fingerprints from %s\n", len(suppressList), c.SuppressFile)
	}

	// SIGHUP hot-reloads the signatures file into the running engine without a
	// restart — so a long-running monitor can pick up new rules while keeping its
	// in-memory ETag, poll cadence, and seen-commit dedup set intact. A failed
	// reload (missing file, bad TOML, empty rule set) is logged and ignored: the
	// previously loaded rules stay active so a typo never silences the monitor.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				reloadSignatures(engine, c.SignaturesPath)
			}
		}
	}()

	provider := ghprovider.NewWithBaseURL(c.GitHubToken, "https://api.github.com")
	provider.DetectForcePush = c.ForcePush
	fetcher := fetch.NewGitHubFetcher(c.GitHubToken, "https://api.github.com")
	if c.ForcePush {
		fmt.Fprintf(os.Stderr, "séance: force-push detection enabled — orphaned diffs will be recovered via the compare API\n")
	}

	// Cumulative counters — all updated atomically.
	var (
		preFilterIn   uint64 // commits reaching pre-filter
		preFilterOut  uint64 // commits surviving pre-filter
		fetchIssued   uint64 // fetch requests issued
		findingsTotal uint64 // findings emitted across all rules
	)

	start := time.Now()

	// logMetrics writes one key=value metrics line to stderr.
	// Called every 60s by the ticker goroutine and on every shutdown path.
	logMetrics := func() {
		elapsed := time.Since(start).Hours()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		in := atomic.LoadUint64(&preFilterIn)
		out := atomic.LoadUint64(&preFilterOut)
		fetched := atomic.LoadUint64(&fetchIssued)
		findings := atomic.LoadUint64(&findingsTotal)
		provPush := atomic.LoadUint64(&provider.Metrics.PushEventsReceived)
		provForcePush := atomic.LoadUint64(&provider.Metrics.ForcePushesReceived)
		provFetch := atomic.LoadUint64(&provider.Metrics.FetchRequests)
		rlRemaining := atomic.LoadInt64(&provider.Metrics.RateLimitRemaining)
		rlReset := atomic.LoadInt64(&provider.Metrics.RateLimitReset)

		survivalPct := 0.0
		if in > 0 {
			survivalPct = float64(out) / float64(in) * 100
		}
		resetIn := int64(-1)
		if rlReset > 0 {
			resetIn = rlReset - time.Now().Unix()
		}

		stMu.Lock()
		seenTracked := len(st.SeenCommits)
		seenFindingsTracked := len(st.SeenFindings)
		stMu.Unlock()

		findingsSuppressed := engine.SuppressedCount()

		var alertsSent, alertsFailed, alertsDropped uint64
		if webhookSink != nil {
			alertsSent, alertsFailed, alertsDropped = webhookSink.Stats()
		}

		fmt.Fprintf(os.Stderr,
			"séance metrics ts=%d push_events_total=%d force_pushes_total=%d prefilter_passed_total=%d prefilter_dropped_total=%d fetches_total=%d polls_total=%d findings_total=%d findings_suppressed_total=%d seen_commits_tracked=%d seen_findings_tracked=%d alerts_sent_total=%d alerts_failed_total=%d alerts_dropped_total=%d push_events_hr=%.1f prefilter_survival_pct=%.1f fetches_hr=%.1f polls_hr=%.1f rate_limit_remaining=%d rate_limit_reset_in=%d\n",
			time.Now().Unix(),
			provPush,
			provForcePush,
			out,
			in-out,
			fetched,
			provFetch,
			findings,
			findingsSuppressed,
			seenTracked,
			seenFindingsTracked,
			alertsSent,
			alertsFailed,
			alertsDropped,
			float64(provPush)/elapsed,
			survivalPct,
			float64(fetched)/elapsed,
			float64(provFetch)/elapsed,
			rlRemaining,
			resetIn,
		)
	}

	// evict trims stale seen-commit entries under the state mutex.
	evict := func() {
		stMu.Lock()
		st.Evict(seenTTL)
		stMu.Unlock()
	}

	// Periodic metrics reporter — fires every 60s.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				logMetrics()
			}
		}
	}()

	// Periodic seen-commit eviction — fires every 5 minutes so the SeenCommits
	// map (and the persisted state file) stays bounded by the TTL.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				evict()
			}
		}
	}()

	events, errs := provider.Stream(ctx)
	for {
		select {
		case event, ok := <-events:
			if !ok {
				logMetrics()
				return nil
			}
			stMu.Lock()
			seen := st.Seen(event.CommitSHA)
			if !seen {
				st.Mark(event.CommitSHA)
			}
			stMu.Unlock()
			if seen {
				continue
			}
			atomic.AddUint64(&preFilterIn, 1)

			decision := prefilter.Filter(event)
			if !decision.Keep {
				continue
			}
			atomic.AddUint64(&preFilterOut, 1)

			if decision.Files == nil {
				// File paths were not in the event payload (new GitHub API format),
				// or this is a force-push. For a force-push we recover the diff that
				// was orphaned by the history rewrite via the compare API; otherwise
				// FetchAll retrieves the head commit's changed files. Either way we
				// then apply post-fetch path filtering.
				atomic.AddUint64(&fetchIssued, 1)
				var (
					all []fetch.FileContent
					err error
				)
				if event.ForcePush {
					all, err = fetcher.FetchCompare(ctx, event)
				} else {
					all, err = fetcher.FetchAll(ctx, event)
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "séance: fetchall error: %v\n", err)
					continue
				}
				for _, fc := range all {
					if fc.Skipped || !prefilter.IsInteresting(fc.FileRef.Path) {
						continue
					}
					n, err := engine.Scan(ctx, fc)
					atomic.AddUint64(&findingsTotal, uint64(n))
					if err != nil {
						fmt.Fprintf(os.Stderr, "séance: scan error: %v\n", err)
					}
				}
			} else {
				for _, ref := range decision.Files {
					atomic.AddUint64(&fetchIssued, 1)
					fc, err := fetcher.Fetch(ctx, event, ref)
					if err != nil || fc.Skipped {
						continue
					}
					n, err := engine.Scan(ctx, fc)
					atomic.AddUint64(&findingsTotal, uint64(n))
					if err != nil {
						fmt.Fprintf(os.Stderr, "séance: scan error: %v\n", err)
					}
				}
			}

		case err := <-errs:
			logMetrics()
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}
			return nil

		case <-ctx.Done():
			logMetrics()
			fmt.Fprintf(os.Stderr, "séance: shutdown complete\n")
			return nil
		}
	}
}

// primaryStdoutSink chooses séance's primary stdout output sink. When --tui is
// set AND stdout is an interactive terminal, it returns the live TUI feed;
// otherwise (no --tui, or stdout redirected to a pipe/file/CI) it returns the
// raw NDJSON sink. This is the graceful-degradation contract: --tui on a
// non-TTY silently becomes NDJSON so downstream consumers are never corrupted by
// terminal escape sequences. The choice changes only presentation — the scan,
// dedup, and alerting path is identical for both.
func primaryStdoutSink(c config.Config) output.Sink {
	if c.TUI && tui.IsTTY(os.Stdout) {
		fmt.Fprintf(os.Stderr, "séance: live terminal feed enabled (--tui)\n")
		return tui.New(tui.Config{Writer: os.Stdout, TTY: true})
	}
	if c.TUI {
		fmt.Fprintf(os.Stderr, "séance: --tui ignored — stdout is not a terminal; falling back to NDJSON\n")
	}
	return ndjson.New(os.Stdout)
}

// parseWebhookHeaders converts repeated "KEY:VALUE" flag strings into a header
// map. The value may itself contain colons (e.g. a URL or a "Bearer x:y" token),
// so only the first colon is treated as the separator. Whitespace around the key
// is trimmed; the value is preserved verbatim after the separator. An entry with
// no colon, or an empty key, is rejected.
func parseWebhookHeaders(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(raw))
	for _, h := range raw {
		idx := strings.Index(h, ":")
		if idx < 0 {
			return nil, fmt.Errorf("invalid header %q: expected KEY:VALUE", h)
		}
		key := strings.TrimSpace(h[:idx])
		val := h[idx+1:]
		if key == "" {
			return nil, fmt.Errorf("invalid header %q: empty key", h)
		}
		headers[key] = val
	}
	return headers, nil
}

// loadSuppressFile reads a newline-delimited list of finding fingerprints from
// path (the .gitleaksignore analogue). Blank lines and lines whose first
// non-space character is '#' are skipped; surrounding whitespace is trimmed off
// each fingerprint. An empty path returns no entries and no error (the feature
// is opt-in). A non-existent path is an error so a typo'd flag fails loudly
// rather than silently disabling the operator's suppress-list.
func loadSuppressFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var fps []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fps = append(fps, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return fps, nil
}

// reloadSignatures re-reads the signatures file at path and swaps the engine's
// active rule set on success. On any failure — unreadable file, malformed TOML,
// or a file that parses to zero rules — it logs to stderr and leaves the
// currently active rules untouched, so a bad edit can never silence a running
// monitor. Triggered by SIGHUP.
func reloadSignatures(engine *scan.Engine, path string) {
	rs, err := ruleset.LoadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "séance: SIGHUP reload failed (%s): %v — keeping %d active rules\n", path, err, engine.RuleCount())
		return
	}
	if len(rs.Rules) == 0 {
		fmt.Fprintf(os.Stderr, "séance: SIGHUP reload skipped (%s): file contains 0 rules — keeping %d active rules\n", path, engine.RuleCount())
		return
	}
	engine.ReloadRules(rs.Rules)
	fmt.Fprintf(os.Stderr, "séance: SIGHUP reload — loaded %d rules from %s\n", len(rs.Rules), path)
}
