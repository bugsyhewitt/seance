// Package ruleset defines the detection rule types for séance.
// The format is compatible with the gitleaks TOML rule format (MIT-licensed),
// enabling community rule contributions and interoperability.
//
// DO NOT copy TruffleHog detectors — TruffleHog is AGPL-3.0. Use only
// gitleaks-format rules (MIT) to keep séance MIT-clean.
package ruleset

import (
	"os"
	"strings"

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

// Select applies operator rule-level selection to a slice of rules and returns
// the rules that survive, in their original order. It is the gitleaks
// --enable-rule / --disable-rule analogue: a way to turn an individual rule on
// or off by ID at deploy time, without editing the signatures TOML.
//
// Semantics (matching gitleaks):
//
//   - enable (allowlist): when non-empty, ONLY rules whose ID is in enable are
//     considered; every other rule is dropped. When empty, every rule is
//     considered (the prior behaviour).
//   - disable (denylist): any rule whose ID is in disable is then removed from
//     whatever the enable step left. disable always wins over enable, so listing
//     the same ID in both yields a dropped rule.
//
// Matching is case-insensitive on the rule ID (rule IDs are conventionally
// lowercase-kebab, and an operator typing a different case should still hit the
// rule they mean). Blank entries in either list are ignored. A nil/empty enable
// and a nil/empty disable returns the input rules unchanged (the byte-for-byte
// prior behaviour), so the feature is purely opt-in.
//
// Select does not mutate the input slice; it returns a new slice referencing the
// same Rule values.
func Select(rules []Rule, enable, disable []string) []Rule {
	enableSet := idSet(enable)
	disableSet := idSet(disable)
	if len(enableSet) == 0 && len(disableSet) == 0 {
		return rules
	}

	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		id := strings.ToLower(strings.TrimSpace(r.ID))
		if len(enableSet) > 0 {
			if _, ok := enableSet[id]; !ok {
				continue // not on the allowlist
			}
		}
		if _, ok := disableSet[id]; ok {
			continue // explicitly denied
		}
		out = append(out, r)
	}
	return out
}

// idSet builds a lowercase, whitespace-trimmed set of rule IDs from a flag
// slice, skipping blank entries. It returns nil for an empty/all-blank input so
// callers can cheaply test len(set) == 0 for "no selection on this axis".
func idSet(ids []string) map[string]struct{} {
	if len(ids) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			set[id] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}
