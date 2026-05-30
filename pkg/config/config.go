// Package config defines séance's runtime configuration.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config holds all runtime configuration for séance.
//
// Every operator-facing field carries a `toml:` tag so the entire configuration
// can be expressed in a single versioned TOML file (see Load) instead of a long
// command line — séance's intended deployment is a run-forever monitor under
// systemd/Docker, where a file is far easier to manage than 20+ flags. Flags and
// environment variables always override the file; see runScan for precedence.
type Config struct {
	Version string `toml:"-"`

	// Ingestion
	GitHubToken     string `toml:"github_token" yaml:"github_token"`
	PollIntervalSec int    `toml:"poll_interval_sec" yaml:"poll_interval_sec"`

	// Watch is an optional list of keywords for the targeted/org-scoped Search-API
	// ingestion provider (the gitGraber-style coverage axis). When non-empty,
	// séance ALSO polls GitHub's commit Search API for these keywords — e.g.
	// "acme-corp" or "internal.example.com" — and fans the results into the same
	// pipeline as the global events stream. This catches leaks the events firehose
	// misses (indexed files, repos pushed before séance started, forks). The
	// Search API has its own much stricter quota (30 req/min authenticated), so
	// the search provider governs its own cadence independently of the events
	// poller. Empty disables the search provider; the events stream is always on.
	Watch []string `toml:"watch" yaml:"watch"`

	// WatchSince and WatchUntil optionally scope the Search-API provider to a
	// committer-date window (calendar dates, YYYY-MM-DD). They apply ONLY to the
	// --watch search provider — the global events stream is inherently "now" and
	// has no indexed history to scope. Either bound may be set independently:
	// WatchSince alone means "commits on or after this date", WatchUntil alone
	// means "on or before", both together an inclusive range. The window is
	// rendered into a GitHub committer-date: search qualifier, so the index does
	// the filtering at zero extra request cost. Empty leaves the search corpus
	// unscoped (the prior behavior). Useful to suppress ancient indexed commits
	// (--watch-since last week) or to scope a targeted investigation to a window.
	WatchSince string `toml:"watch_since" yaml:"watch_since"`
	WatchUntil string `toml:"watch_until" yaml:"watch_until"`

	// WatchIntervalSec tunes the normal cadence, in seconds, between full sweeps
	// of the --watch keyword list by the Search-API provider. It applies ONLY to
	// the search provider — the global events stream uses PollIntervalSec — and
	// has no effect unless --watch keywords are configured. 0 (the default) keeps
	// the provider's built-in 90s cadence, which is conservative for a
	// multi-keyword watch list. A single-keyword targeted investigation can poll
	// faster; a background monitor sharing a token may prefer to poll slower to
	// conserve the 30 req/min Search-API quota. Values below the provider's 10s
	// floor are clamped up (with a stderr warning) so a too-eager interval cannot
	// trap séance in perpetual rate-limit backoff. The separate low-budget backoff
	// cadence is unaffected, so tuning this never weakens the quota protection.
	WatchIntervalSec int `toml:"watch_interval_sec" yaml:"watch_interval_sec"`

	// Pre-filter
	MaxFilesPerCommit int `toml:"max_files_per_commit" yaml:"max_files_per_commit"`

	// ForcePush enables detection of force-push (history-rewrite) events and
	// recovery of the orphaned diff via the compare API. Highest-signal source
	// for intentional secret removal; adds one compare request per force-push.
	ForcePush bool `toml:"force_push" yaml:"force_push"`

	// Scan
	SignaturesPath string  `toml:"signatures_path" yaml:"signatures_path"`
	EntropyThresh  float64 `toml:"entropy_threshold" yaml:"entropy_threshold"`

	// EnableRules and DisableRules apply rule-level selection to the loaded
	// signatures by rule ID — the gitleaks --enable-rule / --disable-rule
	// analogue. They let an operator turn an individual rule on or off at deploy
	// time without editing (or forking) the shared signatures TOML.
	//
	// Semantics: when EnableRules is non-empty it is an allowlist — ONLY rules
	// whose ID appears in it survive, every other rule is dropped. DisableRules is
	// then a denylist applied on top — any rule whose ID appears in it is removed
	// from whatever EnableRules left. DisableRules always wins over EnableRules.
	// Matching is case-insensitive on the rule ID. Both empty (the default) leaves
	// the full loaded ruleset active — byte-for-byte the prior behaviour.
	//
	// The selection is re-applied on every SIGHUP hot-reload, so a long-running
	// monitor keeps honouring the operator's enable/disable choice even after the
	// signatures file changes underneath it.
	EnableRules  []string `toml:"enable_rules" yaml:"enable_rules"`
	DisableRules []string `toml:"disable_rules" yaml:"disable_rules"`

	// MinConfidence is a global confidence floor in [0.0, 1.0]. Any finding whose
	// computed confidence score is below it is dropped before it reaches ANY sink —
	// stdout/NDJSON, --output-file, --sarif-file, --tui, and the webhook — so the
	// operator surfaces only high-confidence findings everywhere at once. At
	// firehose scale alert fatigue is the failure mode that gets a monitor turned
	// off; this is the single dial that trades recall for precision across the whole
	// tool. 0 (the default) admits every finding, identical to prior behavior.
	// Distinct from WebhookMinConfidence, which gates only the webhook channel and
	// is applied on top of this engine-wide floor.
	MinConfidence float64 `toml:"min_confidence" yaml:"min_confidence"`

	// IncludeTags and ExcludeTags are a categorical output filter on a finding's
	// rule tags — the credential-class complement to the numeric MinConfidence
	// floor. When IncludeTags is non-empty, only findings whose rule carries at
	// least one of the listed tags reach ANY sink (stdout/NDJSON, --output-file,
	// --sarif-file, --tui, the webhook); every other finding is dropped before the
	// dedup/sink fan-out. ExcludeTags drops any finding whose rule carries a listed
	// tag. When a tag appears on both lists, ExcludeTags wins. Matching is
	// case-insensitive. Both empty (the default) impose no tag filtering —
	// byte-for-byte the prior behavior. This lets an operator narrow a firehose to
	// just the classes they hunt (e.g. --tag aws,gcp) or silence a noisy class
	// (e.g. --exclude-tag generic) across every sink at once, without editing the
	// ruleset. Applied on top of, and independently from, MinConfidence: a finding
	// must clear both gates to emit.
	IncludeTags []string `toml:"include_tags" yaml:"include_tags"`
	ExcludeTags []string `toml:"exclude_tags" yaml:"exclude_tags"`

	// RateLimit caps the AGGREGATE outbound request rate (requests per second)
	// across every séance HTTP surface — the events provider, the targeted
	// Search-API provider, the diff fetcher, and any future provider — using a
	// single shared token bucket. Each provider's own adaptive backoff
	// (X-RateLimit-Remaining / X-Poll-Interval) keeps it inside its OWN quota
	// window but is blind to the others; --rate-limit is the single dial that
	// caps total throughput across all three surfaces in one place. The
	// dominant use cases are sharing a GitHub token with another tool, running
	// séance inside a low-budget sidecar, or sitting behind a rate-limited
	// outbound proxy. 0 (the default) disables the cap entirely — no limiter
	// is constructed and the prior behaviour is preserved byte-for-byte. The
	// burst is bounded to ceil(RateLimit) so a quiet period cannot amortise
	// into an unbounded spike (matching the intuitive reading of "5 req/s").
	// Requests that have to wait for a token are counted in
	// rate_limit_throttled_total on the periodic metrics line so an operator
	// can tell whether the cap is binding or just decorative. A negative value
	// is rejected at startup as a typo.
	RateLimit float64 `toml:"rate_limit" yaml:"rate_limit"`

	// State
	StateDir    string `toml:"state_dir" yaml:"state_dir"`
	SeenTTLDays int    `toml:"seen_ttl_days" yaml:"seen_ttl_days"`

	// DedupeWindowDays tunes the retention window, in days, of the cross-run
	// finding seen-set (the privacy-preserving fingerprint map persisted in
	// state.json that suppresses re-leaks — the same secret re-pushed, forked,
	// or matched by two overlapping rules alerts once, not every time it
	// reappears). It is the finding-side complement to SeenTTLDays, which
	// governs the per-commit dedup map.
	//
	// 0 (the default) inherits SeenTTLDays — byte-for-byte the prior behaviour
	// where both maps share a single retention window. A non-zero value lets
	// an operator widen finding suppression (e.g. 30 days, so a re-pushed
	// secret stays quiet for a month even though commit dedup expires at 7
	// days) or tighten it (e.g. 1 day, so a legitimate rotation re-alerts
	// quickly) without affecting the commit-side bound. A negative value is
	// rejected at startup as a typo.
	//
	// The tighter window is in effect at all times: a fingerprint older than
	// DedupeWindowDays is evicted on the next sweep and a re-occurrence will
	// re-alert. The shared eviction goroutine (every 5 minutes) and the final
	// pre-shutdown sweep both apply the split TTLs in a single pass.
	DedupeWindowDays int `toml:"dedupe_window_days" yaml:"dedupe_window_days"`

	// SuppressFile is an optional path to a newline-delimited list of finding
	// fingerprints (the .gitleaksignore analogue). Any finding whose fingerprint
	// appears in this file is never emitted or alerted — the operator's
	// always-ignore list for known false positives. Blank lines and lines
	// beginning with '#' are ignored. Cross-run re-leak suppression (identical
	// findings seen in a prior run) is always on and needs no flag.
	SuppressFile string `toml:"suppress_file" yaml:"suppress_file"`

	// Output
	// OutputFormat selects the primary stdout streaming sink: "json" (NDJSON, the
	// default) or "text" (one compact, human-readable, grep-friendly line per
	// finding). It governs only stdout; SARIF is a document written via SarifPath
	// (--sarif-file), not a stream, so "sarif" is rejected here with a hint. When
	// --tui takes over an interactive stdout this is ignored (the live feed wins).
	// An unsupported value fails the run loudly rather than being silently ignored.
	OutputFormat string `toml:"output_format" yaml:"output_format"` // "json" (default) | "text"
	OutputPath   string `toml:"output_path" yaml:"output_path"`     // "-" for stdout

	// OutputMaxBytes bounds the size of the --output-file NDJSON record by
	// rotating it. séance's intended deployment is a run-forever monitor, where
	// the append-only --output-file grows without limit and eventually fills the
	// disk. When OutputMaxBytes > 0 the active file is rotated before any write
	// that would carry it past this size: the active file is renamed to
	// <path>.1 (shifting older generations up, keeping a small fixed number) and
	// a fresh file is opened. Total on-disk footprint is therefore bounded to
	// roughly (kept_generations + 1) * OutputMaxBytes. 0 (the default) disables
	// rotation — byte-for-byte the prior append-forever behaviour. Ignored unless
	// --output-file names a real file (not stdout).
	OutputMaxBytes int64 `toml:"output_max_bytes" yaml:"output_max_bytes"`

	// OutputLimit caps the total number of findings emitted to every sink in a
	// single run. When OutputLimit > 0, séance counts each emitted finding (after
	// the confidence floor, tag filter, placeholder filter, and dedup/suppress
	// layers — i.e. only findings that actually reached the sink fan-out) and
	// triggers a clean shutdown the moment the cap is reached. The in-flight scan
	// completes, every sink's Close is honoured (so a buffered SARIF document is
	// still written and the webhook queue is still drained), and state is
	// persisted on the way out — the same exit path as SIGINT/SIGTERM. The cap
	// applies engine-wide: every sink (stdout/NDJSON, --output-file, --sarif-file,
	// --tui, webhook) sees exactly the same first OutputLimit findings, so a
	// downstream consumer cannot disagree with the SARIF report about how many
	// findings the run produced. 0 (the default) imposes no cap — byte-for-byte
	// the prior behaviour. The dominant use cases are CI gates ("fail the build
	// if N+ findings"), bounded research runs, and demos.
	OutputLimit int `toml:"output_limit" yaml:"output_limit"`

	// SarifPath is an optional path to which séance writes a SARIF 2.1.0 document
	// of all findings observed during the run. SARIF (the OASIS Static Analysis
	// Results Interchange Format) is ingestible by GitHub Advanced Security / code
	// scanning, Azure DevOps, and most SARIF viewers — turning séance's stream into
	// a report a security platform can consume. Unlike the streaming NDJSON sinks,
	// SARIF is a single document, so it is written once on shutdown. The body is
	// built solely from redacted Findings, so the never-store-raw invariant holds.
	// Empty disables the SARIF sink; it composes alongside stdout, --output-file,
	// --tui, and the webhook sink unchanged.
	SarifPath string `toml:"sarif_path" yaml:"sarif_path"`

	// TUI enables the live terminal feed: a scrolling, confidence-colored wall of
	// recent findings with running counters, in place of the raw NDJSON stream on
	// stdout. It is purely a presentation change to the primary sink — coverage,
	// dedup, and alerting are unaffected. When stdout is not an interactive
	// terminal (a pipe, a file, CI), séance silently falls back to NDJSON so
	// downstream consumers are never corrupted by escape sequences.
	TUI bool `toml:"tui" yaml:"tui"`

	// Webhook alerting sink. When WebhookURL is non-empty, each Finding (above
	// WebhookMinConfidence) is POSTed as JSON to the endpoint in addition to the
	// stdout NDJSON stream. Delivery is non-blocking: a slow or dead endpoint
	// never stalls or fails the scan.
	WebhookURL           string   `toml:"webhook_url" yaml:"webhook_url"`
	WebhookHeaders       []string `toml:"webhook_headers" yaml:"webhook_headers"`               // each "Key:Value"
	WebhookMinConfidence float64  `toml:"webhook_min_confidence" yaml:"webhook_min_confidence"` // only alert at/above this score
	// WebhookFormat selects the POST body shape: "json" (the redacted Finding
	// object, default), "slack" (a Slack-compatible {"text": ...} envelope), or
	// "discord" (a Discord-compatible {"content": ...} envelope). Slack/Discord
	// let --webhook-url point straight at an incoming webhook with no relay.
	WebhookFormat string `toml:"webhook_format" yaml:"webhook_format"`

	// WebhookListenAddr is the TCP address on which séance runs an inbound GitHub
	// push-webhook receiver, e.g. ":8099" or "127.0.0.1:8099". When non-empty,
	// séance starts a webhookrecv provider that acts on each push delivery the
	// instant it arrives — no polling, no rate-limit budget, near-zero latency.
	// This is additive: it fans CommitEvents into the same pipeline as the global
	// events stream and the --watch search provider.
	// Empty disables the receiver (default).
	WebhookListenAddr string `toml:"webhook_listen_addr" yaml:"webhook_listen_addr"`

	// WebhookListenSecret is the HMAC-SHA256 secret configured on the GitHub
	// webhook ("Secret" field). When non-empty, every delivery's
	// X-Hub-Signature-256 is verified before the body is parsed. Running without
	// a secret is allowed (private-network / sidecar deployments) but séance logs
	// a warning. Ignored when WebhookListenAddr is empty.
	WebhookListenSecret string `toml:"webhook_listen_secret" yaml:"webhook_listen_secret"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() Config {
	return Config{
		Version:           "0.1.0-dev",
		PollIntervalSec:   60,
		MaxFilesPerCommit: 50,
		ForcePush:         true,
		SignaturesPath:    "signatures/default.toml",
		EntropyThresh:     3.5,
		StateDir:          ".seance",
		SeenTTLDays:       7,
		OutputFormat:      "json",
		OutputPath:        "-",
	}
}

// Load reads a TOML configuration file at path and returns a Config seeded with
// Defaults() and overlaid with every value the file sets. Fields the file omits
// keep their default. The returned Config is the file layer of séance's
// configuration precedence; the caller is responsible for letting explicitly-set
// command-line flags and environment variables override it on top (defaults <
// file < flags/env).
//
// path must exist and parse as valid TOML; a missing file or a parse error is
// returned as an error rather than silently ignored, so a typo in --config never
// causes séance to run with surprising defaults. An unknown key in the file is
// likewise an error — an operator misspelling "webhook_url" should be told, not
// have the alert channel silently disabled.
//
// Load never touches the network, never reads secrets from anywhere but the
// file, and preserves the never-store-raw invariant (it only populates Config,
// which carries no raw secret material).
func Load(path string) (Config, error) {
	c := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config file %q: %w", path, err)
	}

	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return Config{}, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return Config{}, fmt.Errorf("config file %q has unknown key(s): %v", path, keys)
	}

	// Version is an internal build constant, never operator-set; keep the binary's.
	c.Version = Defaults().Version
	return c, nil
}
