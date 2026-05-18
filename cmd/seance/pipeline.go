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

	// Instrumentation counters.
	var (
		preFilterIn  uint64 // commits reaching pre-filter
		preFilterOut uint64 // commits surviving pre-filter
		fetchIssued  uint64 // fetch requests issued
	)

	// Periodic metrics reporter — logs real numbers every 60s.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		start := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				elapsed := time.Since(start).Hours()
				if elapsed < 0.001 {
					elapsed = 0.001
				}
				in := atomic.LoadUint64(&preFilterIn)
				out := atomic.LoadUint64(&preFilterOut)
				fetched := atomic.LoadUint64(&fetchIssued)
				provPush := atomic.LoadUint64(&provider.Metrics.PushEventsReceived)
				provFetch := atomic.LoadUint64(&provider.Metrics.FetchRequests)
				rlRemaining := atomic.LoadInt64(&provider.Metrics.RateLimitRemaining)
				rlReset := atomic.LoadInt64(&provider.Metrics.RateLimitReset)

				survivalPct := 0.0
				if in > 0 {
					survivalPct = float64(out) / float64(in) * 100
				}
				resetIn := ""
				if rlReset > 0 {
					resetIn = fmt.Sprintf(", resets in %ds", rlReset-time.Now().Unix())
				}

				fmt.Fprintf(os.Stderr,
					"séance metrics │ push_events/hr=%.0f │ commits_to_prefilter/hr=%.0f │ prefilter_survival=%.1f%% │ fetches/hr=%.0f │ api_polls/hr=%.0f │ rate_limit_remaining=%d%s\n",
					float64(provPush)/elapsed,
					float64(in)/elapsed,
					survivalPct,
					float64(fetched)/elapsed,
					float64(provFetch)/elapsed,
					rlRemaining,
					resetIn,
				)
			}
		}
	}()

	events, errs := provider.Stream(ctx)
	for {
		select {
		case event, ok := <-events:
			if !ok {
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

			for _, ref := range decision.Files {
				atomic.AddUint64(&fetchIssued, 1)
				fc, err := fetcher.Fetch(ctx, event, ref)
				if err != nil || fc.Skipped {
					continue
				}
				if _, err := engine.Scan(ctx, fc); err != nil {
					fmt.Fprintf(os.Stderr, "séance: scan error: %v\n", err)
				}
			}

		case err := <-errs:
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}
			return nil

		case <-ctx.Done():
			return nil
		}
	}
}
