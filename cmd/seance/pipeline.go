package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	defer func() {
		st.LastUpdated = time.Now()
		_ = store.Save(st)
	}()

	sink := ndjson.New(os.Stdout)
	defer sink.Close()

	engine := scan.New(rs.Rules, sink)
	provider := ghprovider.NewWithBaseURL(c.GitHubToken, "https://api.github.com")
	fetcher := fetch.NewGitHubFetcher(c.GitHubToken, "https://api.github.com")

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

		fmt.Fprintf(os.Stderr,
			"séance metrics ts=%d push_events_total=%d prefilter_passed_total=%d prefilter_dropped_total=%d fetches_total=%d polls_total=%d findings_total=%d push_events_hr=%.1f prefilter_survival_pct=%.1f fetches_hr=%.1f polls_hr=%.1f rate_limit_remaining=%d rate_limit_reset_in=%d\n",
			time.Now().Unix(),
			provPush,
			out,
			in-out,
			fetched,
			provFetch,
			findings,
			float64(provPush)/elapsed,
			survivalPct,
			float64(fetched)/elapsed,
			float64(provFetch)/elapsed,
			rlRemaining,
			resetIn,
		)
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

	events, errs := provider.Stream(ctx)
	for {
		select {
		case event, ok := <-events:
			if !ok {
				logMetrics()
				return nil
			}
			if st.Seen(event.CommitSHA) {
				continue
			}
			st.Mark(event.CommitSHA)
			atomic.AddUint64(&preFilterIn, 1)

			decision := prefilter.Filter(event)
			if !decision.Keep {
				continue
			}
			atomic.AddUint64(&preFilterOut, 1)

			if decision.Files == nil {
				// File paths were not in the event payload (new GitHub API format).
				// FetchAll retrieves all changed files; we then apply path filtering.
				atomic.AddUint64(&fetchIssued, 1)
				all, err := fetcher.FetchAll(ctx, event)
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
