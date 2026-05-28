// Package config defines séance's runtime configuration.
package config

// Config holds all runtime configuration for séance.
type Config struct {
	Version string

	// Ingestion
	GitHubToken     string `yaml:"github_token"`
	PollIntervalSec int    `yaml:"poll_interval_sec"`

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

	// Output
	OutputFormat string `yaml:"output_format"` // "json", "sarif" (v0.3+)
	OutputPath   string `yaml:"output_path"`   // "-" for stdout

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
