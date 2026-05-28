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

	// Pre-filter
	MaxFilesPerCommit int `yaml:"max_files_per_commit"`

	// ForcePush enables detection of force-push (history-rewrite) events and
	// recovery of the orphaned diff via the compare API. Highest-signal source
	// for intentional secret removal; adds one compare request per force-push.
	ForcePush bool `yaml:"force_push"`

	// Scan
	SignaturesPath string  `yaml:"signatures_path"`
	EntropyThresh  float64 `yaml:"entropy_threshold"`

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
