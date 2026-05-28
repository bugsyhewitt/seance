package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/fetch"
	ghprovider "github.com/bugsyhewitt/seance/internal/ingestion/github"
	"github.com/bugsyhewitt/seance/internal/output/ndjson"
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

	sink := ndjson.New(os.Stdout)
	defer sink.Close()

	engine := scan.New(rs.Rules, sink)
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
		stMu.Unlock()

		fmt.Fprintf(os.Stderr,
			"séance metrics ts=%d push_events_total=%d force_pushes_total=%d prefilter_passed_total=%d prefilter_dropped_total=%d fetches_total=%d polls_total=%d findings_total=%d seen_commits_tracked=%d push_events_hr=%.1f prefilter_survival_pct=%.1f fetches_hr=%.1f polls_hr=%.1f rate_limit_remaining=%d rate_limit_reset_in=%d\n",
			time.Now().Unix(),
			provPush,
			provForcePush,
			out,
			in-out,
			fetched,
			provFetch,
			findings,
			seenTracked,
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
