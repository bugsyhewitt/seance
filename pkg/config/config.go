// Package config defines séance's runtime configuration.
package config

// Config holds all runtime configuration for séance.
type Config struct {
	Version string

	// Ingestion
	GitHubToken     string `yaml:"github_token"`
	PollIntervalSec int    `yaml:"poll_interval_sec"`

	// Watch is an optional list of keywords for the targeted/org-scoped Search-API
	// ingestion provider (the gitGraber-style coverage axis). When non-empty,
	// séance ALSO polls GitHub's commit Search API for these keywords — e.g.
	// "acme-corp" or "internal.example.com" — and fans the results into the same
	// pipeline as the global events stream. This catches leaks the events firehose
	// misses (indexed files, repos pushed before séance started, forks). The
	// Search API has its own much stricter quota (30 req/min authenticated), so
	// the search provider governs its own cadence independently of the events
	// poller. Empty disables the search provider; the events stream is always on.
	Watch []string `yaml:"watch"`

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
	WatchSince string `yaml:"watch_since"`
	WatchUntil string `yaml:"watch_until"`

	// Pre-filter
	MaxFilesPerCommit int `yaml:"max_files_per_commit"`

	// ForcePush enables detection of force-push (history-rewrite) events and
	// recovery of the orphaned diff via the compare API. Highest-signal source
	// for intentional secret removal; adds one compare request per force-push.
	ForcePush bool `yaml:"force_push"`

	// Scan
	SignaturesPath string  `yaml:"signatures_path"`
	EntropyThresh  float64 `yaml:"entropy_threshold"`

	// MinConfidence is a global confidence floor in [0.0, 1.0]. Any finding whose
	// computed confidence score is below it is dropped before it reaches ANY sink —
	// stdout/NDJSON, --output-file, --sarif-file, --tui, and the webhook — so the
	// operator surfaces only high-confidence findings everywhere at once. At
	// firehose scale alert fatigue is the failure mode that gets a monitor turned
	// off; this is the single dial that trades recall for precision across the whole
	// tool. 0 (the default) admits every finding, identical to prior behavior.
	// Distinct from WebhookMinConfidence, which gates only the webhook channel and
	// is applied on top of this engine-wide floor.
	MinConfidence float64 `yaml:"min_confidence"`

	// State
	StateDir    string `yaml:"state_dir"`
	SeenTTLDays int    `yaml:"seen_ttl_days"`

	// SuppressFile is an optional path to a newline-delimited list of finding
	// fingerprints (the .gitleaksignore analogue). Any finding whose fingerprint
	// appears in this file is never emitted or alerted — the operator's
	// always-ignore list for known false positives. Blank lines and lines
	// beginning with '#' are ignored. Cross-run re-leak suppression (identical
	// findings seen in a prior run) is always on and needs no flag.
	SuppressFile string `yaml:"suppress_file"`

	// Output
	OutputFormat string `yaml:"output_format"` // "json", "sarif" (v0.3+)
	OutputPath   string `yaml:"output_path"`   // "-" for stdout

	// SarifPath is an optional path to which séance writes a SARIF 2.1.0 document
	// of all findings observed during the run. SARIF (the OASIS Static Analysis
	// Results Interchange Format) is ingestible by GitHub Advanced Security / code
	// scanning, Azure DevOps, and most SARIF viewers — turning séance's stream into
	// a report a security platform can consume. Unlike the streaming NDJSON sinks,
	// SARIF is a single document, so it is written once on shutdown. The body is
	// built solely from redacted Findings, so the never-store-raw invariant holds.
	// Empty disables the SARIF sink; it composes alongside stdout, --output-file,
	// --tui, and the webhook sink unchanged.
	SarifPath string `yaml:"sarif_path"`

	// TUI enables the live terminal feed: a scrolling, confidence-colored wall of
	// recent findings with running counters, in place of the raw NDJSON stream on
	// stdout. It is purely a presentation change to the primary sink — coverage,
	// dedup, and alerting are unaffected. When stdout is not an interactive
	// terminal (a pipe, a file, CI), séance silently falls back to NDJSON so
	// downstream consumers are never corrupted by escape sequences.
	TUI bool `yaml:"tui"`

	// Webhook alerting sink. When WebhookURL is non-empty, each Finding (above
	// WebhookMinConfidence) is POSTed as JSON to the endpoint in addition to the
	// stdout NDJSON stream. Delivery is non-blocking: a slow or dead endpoint
	// never stalls or fails the scan.
	WebhookURL           string   `yaml:"webhook_url"`
	WebhookHeaders       []string `yaml:"webhook_headers"`        // each "Key:Value"
	WebhookMinConfidence float64  `yaml:"webhook_min_confidence"` // only alert at/above this score
	// WebhookFormat selects the POST body shape: "json" (the redacted Finding
	// object, default), "slack" (a Slack-compatible {"text": ...} envelope), or
	// "discord" (a Discord-compatible {"content": ...} envelope). Slack/Discord
	// let --webhook-url point straight at an incoming webhook with no relay.
	WebhookFormat string `yaml:"webhook_format"`

	// WebhookListenAddr is the TCP address on which séance runs an inbound GitHub
	// push-webhook receiver, e.g. ":8099" or "127.0.0.1:8099". When non-empty,
	// séance starts a webhookrecv provider that acts on each push delivery the
	// instant it arrives — no polling, no rate-limit budget, near-zero latency.
	// This is additive: it fans CommitEvents into the same pipeline as the global
	// events stream and the --watch search provider.
	// Empty disables the receiver (default).
	WebhookListenAddr string `yaml:"webhook_listen_addr"`

	// WebhookListenSecret is the HMAC-SHA256 secret configured on the GitHub
	// webhook ("Secret" field). When non-empty, every delivery's
	// X-Hub-Signature-256 is verified before the body is parsed. Running without
	// a secret is allowed (private-network / sidecar deployments) but séance logs
	// a warning. Ignored when WebhookListenAddr is empty.
	WebhookListenSecret string `yaml:"webhook_listen_secret"`
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
