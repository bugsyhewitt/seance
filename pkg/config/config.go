// Package config defines séance's runtime configuration.
package config

// Config holds all runtime configuration for séance.
type Config struct {
	Version string

	// Ingestion
	GitHubToken    string `yaml:"github_token"`
	PollIntervalSec int   `yaml:"poll_interval_sec"`

	// Pre-filter
	MaxFilesPerCommit int `yaml:"max_files_per_commit"`

	// Scan
	SignaturesPath string  `yaml:"signatures_path"`
	EntropyThresh  float64 `yaml:"entropy_threshold"`

	// State
	StateDir    string        `yaml:"state_dir"`
	SeenTTLDays int           `yaml:"seen_ttl_days"`

	// Output
	OutputFormat string `yaml:"output_format"` // "json", "sarif" (v0.3+)
	OutputPath   string `yaml:"output_path"`   // "-" for stdout
}

// Defaults returns a Config with sensible defaults.
func Defaults() Config {
	return Config{
		Version:           "0.1.0-dev",
		PollIntervalSec:   60,
		MaxFilesPerCommit: 50,
		SignaturesPath:    "signatures/default.toml",
		EntropyThresh:     3.5,
		StateDir:          ".seance",
		SeenTTLDays:       7,
		OutputFormat:      "json",
		OutputPath:        "-",
	}
}
