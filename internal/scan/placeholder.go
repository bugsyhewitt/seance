package scan

import (
	"strings"
)

// Placeholder / dummy-value suppression — a GLOBAL false-positive filter.
//
// Per-rule allowlists (stopwords, regexes, paths, commits) let a rule author
// silence false positives they anticipate. But the most common class of false
// positive — documentation placeholders, tutorial sample keys, and "fill this
// in" stand-ins — recurs across EVERY credential type and is impractical to
// enumerate rule-by-rule. Tools in the genre (gitleaks, TruffleHog) special-case
// these well-known dummy values centrally for exactly this reason.
//
// This module implements that central filter: a conservative, value-only check
// that suppresses a candidate secret if it carries an unmistakable placeholder
// signature. It runs only on the already-extracted secret value, never touches
// raw material that leaves the process, and is deliberately tight — it must
// never suppress a plausibly-real credential. When in doubt, it lets the finding
// through; precision (no false suppressions) is weighted far above recall here,
// because a suppressed real leak is the catastrophic outcome and a surviving
// dummy is merely noise the entropy gate and confidence score already temper.
//
// The filter is always on but a single global escape hatch — the rule tag
// "no-placeholder-filter" — disables it per rule for the rare case where a rule
// legitimately matches values that resemble placeholders.

// placeholderTokens are case-insensitive substrings that, when present in a
// candidate secret, mark it as a documentation/tutorial/placeholder value rather
// than a live credential. These are words that essentially never appear inside a
// real high-entropy secret but are ubiquitous in sample/dummy values.
//
// Kept deliberately small and unambiguous. Each entry is a word a credential
// issuer would never embed in real key material, but that humans reach for when
// writing a stand-in.
var placeholderTokens = []string{
	"example",
	"placeholder",
	"changeme",
	"change-me",
	"change_me",
	"yourkey",
	"your-key",
	"your_key",
	"your_api_key",
	"your-api-key",
	"yourapikey",
	"yourtoken",
	"your-token",
	"your_token",
	"yoursecret",
	"your-secret",
	"your_secret",
	"insertkey",
	"insert_key",
	"insert-key",
	"insertyour",
	"insert_your",
	"dummykey",
	"dummy_key",
	"dummytoken",
	"faketoken",
	"fake_token",
	"samplekey",
	"sample_key",
	"testkey1234",
	"notarealkey",
	"not_a_real",
	"redacted",
	"xxxxxxxx",                         // 8+ x's: a manual mask, never real key material
	"deadbeef",                         // canonical filler hex
	"0123456789abcdef0123456789abcdef", // textbook sequential hex fill
	"abcdefghijklmnopqrstuvwxyz",       // textbook alphabet fill
	"loremipsum",
}

// maxMonoRun is the longest tolerated run of a single repeated character. A run
// at or beyond this length (e.g. "AKIAAAAAAAAAAAAAAAAA", "ghp_0000...0000") is a
// placeholder mask, not generated key material — a real, randomly generated
// secret has no 8-character mono-character run with overwhelming probability.
// Go's RE2 has no backreferences, so this is detected with a linear scan rather
// than a regex.
const maxMonoRun = 8

// hasLongMonoRun reports whether s contains a run of the same character repeated
// maxMonoRun or more times in a row.
func hasLongMonoRun(s string) bool {
	if len(s) < maxMonoRun {
		return false
	}
	run := 1
	prev := rune(-1)
	for _, c := range s {
		if c == prev {
			run++
			if run >= maxMonoRun {
				return true
			}
		} else {
			run = 1
			prev = c
		}
	}
	return false
}

// noPlaceholderFilterTag, when present in a rule's Tags, disables the global
// placeholder filter for that rule. Escape hatch for the rare rule that
// legitimately matches placeholder-resembling values.
const noPlaceholderFilterTag = "no-placeholder-filter"

// ruleSkipsPlaceholderFilter reports whether the rule opted out of the global
// placeholder filter via the no-placeholder-filter tag.
func ruleSkipsPlaceholderFilter(tags []string) bool {
	for _, t := range tags {
		if t == noPlaceholderFilterTag {
			return true
		}
	}
	return false
}

// isPlaceholder reports whether secretVal is an obvious documentation /
// tutorial / mask placeholder rather than a live credential.
//
// It matches on three unambiguous signatures:
//   - a known placeholder word (case-insensitive substring), or
//   - a run of the same character repeated 8+ times (a manual mask), or
//   - a textbook sequential/alphabet fill.
//
// It operates only on the candidate value held transiently in memory; nothing
// derived from secretVal is logged, persisted, or emitted. The check is
// intentionally conservative — see the package note — so a real, randomly
// generated credential is never suppressed.
func isPlaceholder(secretVal string) bool {
	if secretVal == "" {
		return false
	}
	lower := strings.ToLower(secretVal)
	for _, tok := range placeholderTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	if hasLongMonoRun(secretVal) {
		return true
	}
	return false
}
