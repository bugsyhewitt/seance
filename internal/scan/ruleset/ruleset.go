// Package ruleset defines the detection rule types for séance.
// The format is compatible with the gitleaks TOML rule format (MIT-licensed),
// enabling community rule contributions and interoperability.
//
// DO NOT copy TruffleHog detectors — TruffleHog is AGPL-3.0. Use only
// gitleaks-format rules (MIT) to keep séance MIT-clean.
package ruleset

import (
	"os"

	"github.com/BurntSushi/toml"
)

// AllowList specifies patterns that suppress a rule match.
// Compatible with the gitleaks allowlist format.
type AllowList struct {
	Paths     []string `toml:"paths"`     // regex patterns for file paths to skip
	Regexes   []string `toml:"regexes"`   // regex patterns matching false-positive values
	StopWords []string `toml:"stopwords"` // literal strings that indicate a test/dummy value
	Commits   []string `toml:"commits"`   // commit SHAs to skip entirely
}

// Rule is a single detection rule in gitleaks-compatible TOML format.
type Rule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	SecretGroup int      `toml:"secretGroup"` // capture group index for the secret value
	Keywords    []string `toml:"keywords"`    // fast pre-scan strings; rule skipped if none match
	Tags        []string `toml:"tags"`
	Entropy     float64  `toml:"entropy"` // minimum Shannon entropy; 0 = disabled
	// Confidence overrides the engine's default base confidence (0.80) for this
	// rule. A value in (0.0, 1.0] sets the starting score; the engine's
	// specificity, entropy-headroom, and path adjustments still apply on top
	// (the final score is clamped to [0.0, 1.0]). 0 (the default) leaves the
	// rule on the engine's default base — byte-for-byte the prior behaviour.
	// A high-trust prefix rule can declare confidence = 1.0; a noisy generic
	// rule can declare a lower base, all without touching engine code.
	Confidence float64   `toml:"confidence"`
	AllowList  AllowList `toml:"allowlist"`
}

// Ruleset is the top-level container for a séance/gitleaks rules file.
type Ruleset struct {
	Title       string `toml:"title"`
	Description string `toml:"description"`
	Rules       []Rule `toml:"rules"`
}

// LoadFile parses a gitleaks-compatible TOML file into a Ruleset.
func LoadFile(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// Load parses raw TOML bytes into a Ruleset.
func Load(data []byte) (*Ruleset, error) {
	var rs Ruleset
	if err := toml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}
