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
	"github.com/bugsyhewitt/seance/internal/ingestion"
	ghprovider "github.com/bugsyhewitt/seance/internal/ingestion/github"
	searchprovider "github.com/bugsyhewitt/seance/internal/ingestion/search"
	webhookrecvprovider "github.com/bugsyhewitt/seance/internal/ingestion/webhookrecv"
	"github.com/bugsyhewitt/seance/internal/output"
	outfile "github.com/bugsyhewitt/seance/internal/output/file"
	"github.com/bugsyhewitt/seance/internal/output/ndjson"
	"github.com/bugsyhewitt/seance/internal/output/sarif"
	outtext "github.com/bugsyhewitt/seance/internal/output/text"
	"github.com/bugsyhewitt/seance/internal/output/tui"
	"github.com/bugsyhewitt/seance/internal/output/webhook"
	"github.com/bugsyhewitt/seance/internal/prefilter"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
	"github.com/bugsyhewitt/seance/internal/state"
	"github.com/bugsyhewitt/seance/pkg/config"
)

func runPipeline(ctx context.Context, c config.Config) error {
	// Validate the stdout streaming format (--output) up front so an unsupported
	// value fails the run loudly instead of being silently ignored. --output has
	// always been parsed and defaulted to "json" but was never consumed; this is
	// where it finally governs the primary stdout sink.
	if _, err := streamFormat(c.OutputFormat); err != nil {
		return err
	}

	rs, err := ruleset.LoadFile(c.SignaturesPath)
	if err != nil {
		return fmt.Errorf("load signatures: %w", err)
	}
	loaded := len(rs.Rules)
	// Apply operator rule-level selection (--enable-rule / --disable-rule) on top
	// of the loaded signatures, so a rule can be turned on or off by ID without
	// editing the shared TOML. With neither flag set this is a no-op and the full
	// ruleset stays active.
	rules := ruleset.Select(rs.Rules, c.EnableRules, c.DisableRules)
	if len(c.EnableRules) > 0 || len(c.DisableRules) > 0 {
		fmt.Fprintf(os.Stderr, "séance: loaded %d rules from %s, %d active after rule selection (--enable-rule/--disable-rule)\n", loaded, c.SignaturesPath, len(rules))
		if len(rules) == 0 {
			return fmt.Errorf("rule selection left 0 active rules — check --enable-rule/--disable-rule against the rule IDs in %s", c.SignaturesPath)
		}
	} else {
		fmt.Fprintf(os.Stderr, "séance: loaded %d rules from %s\n", loaded, c.SignaturesPath)
	}

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

	// Optional durable NDJSON file sink. When --output-file is set, every finding
	// is ALSO appended (redacted) to that file in addition to whatever is on
	// stdout. This is what lets --tui (which takes over stdout with the live feed)
	// still produce a machine-readable record, and serves as a plain tee otherwise.
	// OutputPath defaults to "-" (stdout, handled by the primary sink); any other
	// value names a real file. Append-mode, so a restart extends the record.
	if c.OutputPath != "" && c.OutputPath != "-" {
		fileSink, ferr := outfile.New(c.OutputPath)
		if ferr != nil {
			return fmt.Errorf("output file: %w", ferr)
		}
		sinks = append(sinks, fileSink)
		fmt.Fprintf(os.Stderr, "séance: writing redacted NDJSON findings to %s\n", c.OutputPath)
	}

	// Optional SARIF report sink. When --sarif-file is set, every finding is ALSO
	// buffered (redacted) and written as a single SARIF 2.1.0 document on shutdown,
	// ingestible by GitHub code scanning and other SARIF tooling. Unlike the
	// streaming sinks it produces one document on Close (ordered before the final
	// state flush by the deferred-Close loop below), so a clean run still emits a
	// valid empty-results report. With --sarif-file unset it is absent entirely and
	// the existing data path is byte-for-byte unchanged.
	if c.SarifPath != "" {
		sarifSink := sarif.New(c.SarifPath, c.Version)
		sinks = append(sinks, sarifSink)
		fmt.Fprintf(os.Stderr, "séance: writing SARIF 2.1.0 report to %s on shutdown\n", c.SarifPath)
	}

	// Optional webhook alerting sink. Constructed only when a URL is configured.
	// Its Close (drain + flush) runs after the stdout sink's, both via defers.
	var webhookSink *webhook.Sink
	if c.WebhookURL != "" {
		headers, herr := parseWebhookHeaders(c.WebhookHeaders)
		if herr != nil {
			return fmt.Errorf("webhook header: %w", herr)
		}
		format, ferr := webhook.ParseFormat(c.WebhookFormat)
		if ferr != nil {
			return fmt.Errorf("webhook format: %w", ferr)
		}
		webhookSink = webhook.New(webhook.Config{
			URL:           c.WebhookURL,
			Headers:       headers,
			MinConfidence: c.WebhookMinConfidence,
			Format:        format,
			ErrLog:        os.Stderr,
		})
		sinks = append(sinks, webhookSink)
		fmt.Fprintf(os.Stderr, "séance: webhook alerting enabled — POSTing findings (confidence >= %.2f, format=%s) to %s\n",
			c.WebhookMinConfidence, format, c.WebhookURL)
	}
	for _, s := range sinks {
		defer s.Close()
	}

	// Global confidence floor (--min-confidence). Validated here so an out-of-range
	// value fails the run loudly rather than silently clamping. When set above 0 it
	// is installed on the engine, which drops sub-threshold findings before the
	// dedup/sink fan-out — so every sink surfaces only high-confidence findings.
	if c.MinConfidence < 0 || c.MinConfidence > 1 {
		return fmt.Errorf("min-confidence must be between 0.0 and 1.0, got %.2f", c.MinConfidence)
	}

	engine := scan.New(rules, sinks...)
	if c.MinConfidence > 0 {
		engine.WithMinConfidence(c.MinConfidence)
		fmt.Fprintf(os.Stderr, "séance: confidence floor enabled — only findings with confidence >= %.2f reach any sink\n", c.MinConfidence)
	}

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
				reloadSignatures(engine, c.SignaturesPath, c.EnableRules, c.DisableRules)
			}
		}
	}()

	provider := ghprovider.NewWithBaseURL(c.GitHubToken, "https://api.github.com")
	provider.DetectForcePush = c.ForcePush
	// Resume conditional polling across restarts: seed the provider with the ETag
	// persisted from the previous run so the first poll is an If-None-Match request
	// (a cheap 304 when nothing new happened) instead of a full cold fetch. The
	// live ETag is written back to state on shutdown in the deferred flush below.
	provider.SeedETag(st.ETag)
	if st.ETag != "" {
		fmt.Fprintf(os.Stderr, "séance: resuming events poll from persisted ETag\n")
	}
	// Capture the provider's latest ETag into state before the final persist. This
	// defer runs before the top-of-function save defer (LIFO), so the saved state
	// carries the freshest conditional-request cursor. Guarded by stMu like every
	// other state mutation so it cannot race the metrics/eviction goroutines.
	defer func() {
		if cur := provider.CurrentETag(); cur != "" {
			stMu.Lock()
			st.ETag = cur
			stMu.Unlock()
		}
	}()
	fetcher := fetch.NewGitHubFetcher(c.GitHubToken, "https://api.github.com")
	if c.ForcePush {
		fmt.Fprintf(os.Stderr, "séance: force-push detection enabled — orphaned diffs will be recovered via the compare API\n")
	}

	// Optional targeted/org-scoped Search-API provider. Constructed only when
	// --watch keywords are supplied. It runs concurrently with the global events
	// stream and fans its CommitEvents into the same downstream pipeline. The
	// Search API has its own (much stricter) quota, so it governs its own cadence.
	// When no keywords are configured the search provider is absent entirely and
	// the events-only path is byte-for-byte unchanged.
	var searchProv *searchprovider.Provider
	if len(c.Watch) > 0 {
		searchProv = searchprovider.NewWithBaseURL(c.GitHubToken, "https://api.github.com", c.Watch...)
		if kw := searchProv.Keywords(); len(kw) > 0 {
			// Optional committer-date scoping (applies only to the search corpus).
			// A bad date or inverted range fails the run loudly rather than
			// silently returning an unscoped firehose.
			if c.WatchSince != "" || c.WatchUntil != "" {
				if derr := searchProv.SetDateRange(c.WatchSince, c.WatchUntil); derr != nil {
					return fmt.Errorf("watch date range: %w", derr)
				}
				fmt.Fprintf(os.Stderr, "séance: search-api committer-date scoped to %s\n", describeWatchWindow(c.WatchSince, c.WatchUntil))
			}
			// Optional cadence override (applies only to the search provider). A
			// value below the provider's floor is clamped up there with its own
			// warning; we report the effective interval so the operator can confirm
			// what séance actually settled on.
			if c.WatchIntervalSec > 0 {
				effective := searchProv.SetPollInterval(time.Duration(c.WatchIntervalSec) * time.Second)
				fmt.Fprintf(os.Stderr, "séance: search-api poll cadence set to %s\n", effective)
			}
			fmt.Fprintf(os.Stderr, "séance: search-api monitoring enabled — watching %d keyword(s) via GET /search/commits\n", len(kw))
		} else {
			searchProv = nil // every keyword was blank
		}
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
		placeholdersDropped := engine.PlaceholderDroppedCount()
		findingsBelowConfidence := engine.BelowConfidenceCount()

		var alertsSent, alertsFailed, alertsDropped uint64
		if webhookSink != nil {
			alertsSent, alertsFailed, alertsDropped = webhookSink.Stats()
		}

		// Search-API provider counters (zero when --watch is not configured).
		var searchReqs, searchResults, searchEmitted uint64
		searchRL := int64(-1)
		if searchProv != nil {
			searchReqs = atomic.LoadUint64(&searchProv.Metrics.SearchRequests)
			searchResults = atomic.LoadUint64(&searchProv.Metrics.ResultsReceived)
			searchEmitted = atomic.LoadUint64(&searchProv.Metrics.CommitsEmitted)
			searchRL = atomic.LoadInt64(&searchProv.Metrics.RateLimitRemaining)
		}

		fmt.Fprintf(os.Stderr,
			"séance metrics ts=%d push_events_total=%d force_pushes_total=%d prefilter_passed_total=%d prefilter_dropped_total=%d fetches_total=%d polls_total=%d findings_total=%d findings_suppressed_total=%d findings_below_confidence_total=%d placeholders_dropped_total=%d seen_commits_tracked=%d seen_findings_tracked=%d alerts_sent_total=%d alerts_failed_total=%d alerts_dropped_total=%d search_requests_total=%d search_results_total=%d search_commits_total=%d search_rate_limit_remaining=%d push_events_hr=%.1f prefilter_survival_pct=%.1f fetches_hr=%.1f polls_hr=%.1f rate_limit_remaining=%d rate_limit_reset_in=%d\n",
			time.Now().Unix(),
			provPush,
			provForcePush,
			out,
			in-out,
			fetched,
			provFetch,
			findings,
			findingsSuppressed,
			findingsBelowConfidence,
			placeholdersDropped,
			seenTracked,
			seenFindingsTracked,
			alertsSent,
			alertsFailed,
			alertsDropped,
			searchReqs,
			searchResults,
			searchEmitted,
			searchRL,
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

	// Fan all configured providers into a single event/error stream. With only the
	// events provider this is a passthrough; with --watch the search provider's
	// stream is merged in, so the scan/dedup/fetch loop below is identical in both
	// cases — multi-provider support is purely additive at the ingestion edge.
	providers := []ingestion.Provider{provider}
	if searchProv != nil {
		providers = append(providers, searchProv)
	}
	// Optional scan-on-push webhook receiver. When --webhook-listen is set,
	// séance runs an inbound HTTP server that scans GitHub push deliveries the
	// instant they arrive — no polling, no rate-limit budget, near-zero latency.
	// It is additive: its CommitEvents fan into the same pipeline as the events
	// stream and the search provider. With --webhook-listen unset it is absent
	// entirely and the events-only path is byte-for-byte unchanged.
	if c.WebhookListenAddr != "" {
		recvProv := webhookrecvprovider.New(c.WebhookListenAddr, "", c.WebhookListenSecret)
		providers = append(providers, recvProv)
	}
	events, errs := mergeProviders(ctx, providers...)
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

// mergeProviders starts every provider's Stream and fans their CommitEvents into
// a single channel, and their errors into a single error channel. The merged
// events channel is closed only after every provider's own events channel has
// closed (each closes on ctx cancellation or an unrecoverable error), so the
// downstream loop sees the same "channel closed ⇒ shutdown" contract it had with
// a single provider. The first error from any provider is forwarded once; the
// error channel is buffered so a provider failing never blocks. Both returned
// channels are always closed when all providers have exited.
func mergeProviders(ctx context.Context, providers ...ingestion.Provider) (<-chan ingestion.CommitEvent, <-chan error) {
	out := make(chan ingestion.CommitEvent, 128)
	errs := make(chan error, 1)

	var wg sync.WaitGroup
	for _, p := range providers {
		evCh, erCh := p.Stream(ctx)
		wg.Add(2)
		// Forward events.
		go func(ev <-chan ingestion.CommitEvent) {
			defer wg.Done()
			for e := range ev {
				select {
				case out <- e:
				case <-ctx.Done():
					return
				}
			}
		}(evCh)
		// Forward the (at most one) error, non-blocking — first writer wins.
		// Counted in the WaitGroup so errs is not closed while a forwarder is
		// still draining a provider's error channel.
		go func(er <-chan error) {
			defer wg.Done()
			for e := range er {
				if e == nil {
					continue
				}
				select {
				case errs <- e:
				default:
				}
			}
		}(erCh)
	}

	go func() {
		wg.Wait()
		close(out)
		close(errs)
	}()

	return out, errs
}

// primaryStdoutSink chooses séance's primary stdout output sink. When --tui is
// set AND stdout is an interactive terminal, it returns the live TUI feed;
// otherwise (no --tui, or stdout redirected to a pipe/file/CI) it returns the
// streaming sink selected by --output (the OutputFormat): NDJSON ("json", the
// default) or the compact human-readable line stream ("text"). This is the
// graceful-degradation contract: --tui on a non-TTY silently becomes the chosen
// stream so downstream consumers are never corrupted by terminal escape
// sequences. The choice changes only presentation — the scan, dedup, and
// alerting path is identical for every option. The format is validated in
// runPipeline before this is called, so the error here is unreachable in
// practice; defaulting to NDJSON is a defensive fallback.
func primaryStdoutSink(c config.Config) output.Sink {
	if c.TUI && tui.IsTTY(os.Stdout) {
		fmt.Fprintf(os.Stderr, "séance: live terminal feed enabled (--tui)\n")
		return tui.New(tui.Config{Writer: os.Stdout, TTY: true})
	}
	format, err := streamFormat(c.OutputFormat)
	if err != nil {
		format = formatJSON
	}
	if c.TUI {
		fmt.Fprintf(os.Stderr, "séance: --tui ignored — stdout is not a terminal; falling back to %s\n", format)
	}
	switch format {
	case formatText:
		return outtext.New(os.Stdout)
	default:
		return ndjson.New(os.Stdout)
	}
}

// Supported --output streaming formats for the primary stdout sink. SARIF is
// deliberately excluded here: it is a single buffered document, not a stream, and
// is produced via --sarif-file; streamFormat points the operator there rather
// than silently accepting a value the stdout path cannot honor.
const (
	formatJSON = "json"
	formatText = "text"
)

// streamFormat normalizes and validates the --output value, returning the
// canonical format name. An empty value defaults to "json" (NDJSON), preserving
// the original behavior. "sarif" is rejected with a hint toward --sarif-file
// because SARIF is a document sink, not a stdout stream. Any other value is an
// error so a typo'd --output fails the run loudly instead of being silently
// ignored (the old behavior, where --output had no effect at all).
func streamFormat(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", formatJSON:
		return formatJSON, nil
	case formatText:
		return formatText, nil
	case "sarif":
		return "", fmt.Errorf("--output sarif is not a stdout stream — SARIF is a document; use --sarif-file PATH instead")
	default:
		return "", fmt.Errorf("unsupported --output format %q: valid streaming formats are %q and %q (for SARIF use --sarif-file)", raw, formatJSON, formatText)
	}
}

// describeWatchWindow renders a human-readable description of the committer-date
// scoping window for the startup log. At least one bound is non-empty when this
// is called (the caller only logs when scoping is active).
func describeWatchWindow(since, until string) string {
	switch {
	case since != "" && until != "":
		return since + ".." + until
	case since != "":
		return "on or after " + since
	default:
		return "on or before " + until
	}
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

// reloadSignatures re-reads the signatures file at path, re-applies the
// operator's rule-level selection (enable/disable), and swaps the engine's
// active rule set on success. On any failure — unreadable file, malformed TOML,
// a file that parses to zero rules, or a selection that leaves zero rules — it
// logs to stderr and leaves the currently active rules untouched, so a bad edit
// (or a selection that no longer matches any rule in the new file) can never
// silence a running monitor. Triggered by SIGHUP.
func reloadSignatures(engine *scan.Engine, path string, enable, disable []string) {
	rs, err := ruleset.LoadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "séance: SIGHUP reload failed (%s): %v — keeping %d active rules\n", path, err, engine.RuleCount())
		return
	}
	if len(rs.Rules) == 0 {
		fmt.Fprintf(os.Stderr, "séance: SIGHUP reload skipped (%s): file contains 0 rules — keeping %d active rules\n", path, engine.RuleCount())
		return
	}
	// Re-apply the same --enable-rule/--disable-rule selection the run started
	// with, so a hot-reloaded ruleset keeps honouring the operator's choice.
	selected := ruleset.Select(rs.Rules, enable, disable)
	if len(selected) == 0 {
		fmt.Fprintf(os.Stderr, "séance: SIGHUP reload skipped (%s): rule selection (--enable-rule/--disable-rule) left 0 of %d rules — keeping %d active rules\n", path, len(rs.Rules), engine.RuleCount())
		return
	}
	engine.ReloadRules(selected)
	if len(enable) > 0 || len(disable) > 0 {
		fmt.Fprintf(os.Stderr, "séance: SIGHUP reload — loaded %d rules from %s, %d active after rule selection\n", len(rs.Rules), path, len(selected))
		return
	}
	fmt.Fprintf(os.Stderr, "séance: SIGHUP reload — loaded %d rules from %s\n", len(rs.Rules), path)
}
