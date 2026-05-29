// Package scan runs the signature engine over fetched file content.
package scan

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// baseConfidence is the starting confidence score for any match that passes
// keyword, regex, and allowlist checks but has no entropy data to work with.
const baseConfidence = 0.80

// highSpecificityBonus is added when the rule has a high-specificity prefix
// pattern (e.g. AKIA, ghp_, xoxb-) — structural patterns that rarely appear
// in non-credential contexts.
const highSpecificityBonus = 0.10

// Engine runs detection rules over fetched file content.
//
// The rule set is guarded by rulesMu so it can be swapped at runtime
// (see ReloadRules) by a signal handler while Scan runs concurrently in
// the pipeline loop. Sinks are fixed for the life of the engine and need
// no locking.
type Engine struct {
	rulesMu sync.RWMutex
	rules   []ruleset.Rule
	sinks   []output.Sink

	// suppressor, when non-nil, decides whether a finding is a cross-run
	// duplicate or an operator-suppressed false positive and should not be
	// emitted to the sinks. It is fixed for the life of the engine.
	suppressor Suppressor

	// suppressed counts findings dropped by the suppressor. Read atomically for
	// the findings_suppressed_total metric.
	suppressed uint64

	// placeholderDropped counts candidate matches dropped by the global
	// placeholder/dummy-value filter (documentation samples, masks, "your_key"
	// stand-ins). Read atomically for the placeholders_dropped_total metric.
	placeholderDropped uint64

	// minConfidence is a global confidence floor in [0.0, 1.0]. Any finding whose
	// computed confidence is below it is dropped before the dedup/sink fan-out, so
	// EVERY sink (stdout, file, SARIF, TUI, webhook) sees only findings at or above
	// the threshold. Zero (the default) admits everything — byte-for-byte the prior
	// behavior. Fixed for the life of the engine.
	minConfidence float64

	// belowConfidence counts candidate findings dropped by the minConfidence
	// floor. Read atomically for the findings_below_confidence_total metric.
	belowConfidence uint64
}

// Suppressor decides whether a finding should be suppressed (not emitted) on the
// basis of its stable fingerprint. It is the consumer-side interface for
// cross-run deduplication and operator suppress-lists; state.State implements it.
//
// Suppress is called once per candidate finding under the engine's care. It must
// be safe for concurrent use — the pipeline scans on a single goroutine today,
// but the engine makes no such guarantee. Implementations should do their own
// locking. A return of true means "drop this finding"; the engine still records
// the fingerprint as seen via MarkSeen so a later identical finding is also
// dropped.
type Suppressor interface {
	// Suppress reports whether the finding with this fingerprint should be
	// dropped — either because it was seen in a prior run/scan or because it is
	// on an operator suppress-list.
	Suppress(fingerprint string) bool
	// MarkSeen records a fingerprint as emitted so subsequent identical findings
	// suppress. Called only for findings that were NOT suppressed.
	MarkSeen(fingerprint string)
}

// New constructs an Engine with the given rules and output sinks.
func New(rules []ruleset.Rule, sinks ...output.Sink) *Engine {
	return &Engine{rules: rules, sinks: sinks}
}

// WithSuppressor returns the engine with the given cross-run suppressor
// installed. Passing nil disables suppression (every finding is emitted). It is
// intended to be called once at construction, before Scan runs.
func (e *Engine) WithSuppressor(s Suppressor) *Engine {
	e.suppressor = s
	return e
}

// WithMinConfidence returns the engine with a global confidence floor installed.
// Any finding whose computed confidence is strictly below threshold is dropped
// before deduplication and sink fan-out, so every configured sink — stdout, file,
// SARIF, TUI, and webhook — only ever sees findings at or above it. A threshold
// of 0 (the default) admits every finding, leaving the prior behavior unchanged.
// Values are clamped to [0.0, 1.0]. Intended to be called once at construction,
// before Scan runs. It is independent of, and applied before, the webhook sink's
// own per-sink MinConfidence gate.
func (e *Engine) WithMinConfidence(threshold float64) *Engine {
	if threshold < 0 {
		threshold = 0
	}
	if threshold > 1 {
		threshold = 1
	}
	e.minConfidence = threshold
	return e
}

// SuppressedCount returns the cumulative number of findings dropped by the
// suppressor. Used for the findings_suppressed_total metric.
func (e *Engine) SuppressedCount() uint64 {
	return atomic.LoadUint64(&e.suppressed)
}

// BelowConfidenceCount returns the cumulative number of findings dropped by the
// global confidence floor (--min-confidence). Used for the
// findings_below_confidence_total metric.
func (e *Engine) BelowConfidenceCount() uint64 {
	return atomic.LoadUint64(&e.belowConfidence)
}

// PlaceholderDroppedCount returns the cumulative number of candidate matches
// dropped by the global placeholder/dummy-value filter. Used for the
// placeholders_dropped_total metric.
func (e *Engine) PlaceholderDroppedCount() uint64 {
	return atomic.LoadUint64(&e.placeholderDropped)
}

// ReloadRules atomically replaces the engine's active rule set. It is safe to
// call concurrently with Scan: an in-flight Scan completes against the snapshot
// it took, and the next Scan picks up the new rules. Passing an empty slice
// disables all detection until the next reload — callers should validate the
// new rule set is non-empty before reloading if that is undesirable.
func (e *Engine) ReloadRules(rules []ruleset.Rule) {
	e.rulesMu.Lock()
	e.rules = rules
	e.rulesMu.Unlock()
}

// RuleCount returns the number of rules currently active. Primarily useful for
// observability and tests after a ReloadRules.
func (e *Engine) RuleCount() int {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()
	return len(e.rules)
}

// Scan runs all rules against content and emits Findings to all sinks.
// Returns the number of findings emitted.
func (e *Engine) Scan(ctx context.Context, content fetch.FileContent) (int, error) {
	if content.Skipped {
		return 0, nil
	}
	// Snapshot the rule set under a read lock so a concurrent ReloadRules
	// (triggered by SIGHUP) cannot mutate the slice mid-iteration. The slice
	// header is copied; the backing array is never mutated in place — reloads
	// install a brand-new slice — so the snapshot stays valid for this scan.
	e.rulesMu.RLock()
	rules := e.rules
	e.rulesMu.RUnlock()

	total := 0
	for _, rule := range rules {
		if !keywordMatch(content.Patch, rule.Keywords) {
			continue
		}
		// File-scoped allowlist short-circuits: if this file's path or this
		// commit is allowlisted for the rule, none of the rule's matches in
		// this file can fire. Both are gitleaks-standard allowlist axes.
		if pathAllowListed(content.FileRef.Path, rule.AllowList.Paths) {
			continue
		}
		if commitAllowListed(content.Event.CommitSHA, rule.AllowList.Commits) {
			continue
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			continue
		}
		for lineNum, line := range content.Lines {
			submatches := re.FindAllStringSubmatch(line, -1)
			for _, submatch := range submatches {
				if len(submatch) == 0 {
					continue
				}
				// fullMatch is the entire regex match.
				fullMatch := submatch[0]

				// secretVal is the candidate secret for entropy + redaction.
				// If the rule specifies a capture group, extract that group;
				// otherwise fall back to the full match.
				secretVal := extractSecret(submatch, rule.SecretGroup)

				if isAllowListed(secretVal, rule.AllowList) || isAllowListed(fullMatch, rule.AllowList) {
					continue
				}

				// Entropy gate: if rule.Entropy > 0, drop matches whose secret
				// value doesn't meet the minimum Shannon entropy threshold.
				// This eliminates common false positives like repeated patterns,
				// dictionary words, and placeholder values that happen to match
				// the regex shape.
				if rule.Entropy > 0 {
					measured := shannonEntropy(secretVal)
					if measured < rule.Entropy {
						continue
					}
				}

				// Global placeholder/dummy-value filter: drop matches that carry
				// an unmistakable documentation-sample, mask, or "fill this in"
				// signature (e.g. "...EXAMPLE", "your_api_key", "ghp_000...000").
				// These recur across every credential type and are the dominant
				// false-positive class at firehose scale, so they are filtered
				// centrally rather than rule-by-rule. The check is conservative —
				// it never suppresses a plausibly-real key — and operates only on
				// the in-memory candidate value (nothing raw is emitted). A rule
				// can opt out with the "no-placeholder-filter" tag.
				if !ruleSkipsPlaceholderFilter(rule.Tags) && isPlaceholder(secretVal) {
					atomic.AddUint64(&e.placeholderDropped, 1)
					continue
				}

				confidence := computeConfidence(rule, secretVal, content.FileRef.Path)

				// Global confidence floor: surface only high-confidence findings.
				// Applied here — before fingerprinting, dedup, and the sink fan-out —
				// so a low-confidence match never reaches ANY sink (stdout, file,
				// SARIF, TUI, webhook) and never consumes a dedup slot. The default
				// floor is 0, which admits everything (unchanged behavior). This is
				// the engine-wide noise gate; the webhook sink keeps its own,
				// independent MinConfidence for finer per-channel tuning above this.
				if confidence < e.minConfidence {
					atomic.AddUint64(&e.belowConfidence, 1)
					continue
				}

				finding := output.Finding{
					RuleID:     rule.ID,
					RuleDesc:   rule.Description,
					Provider:   content.Event.Provider,
					RepoOwner:  content.Event.RepoOwner,
					RepoName:   content.Event.RepoName,
					CommitSHA:  content.Event.CommitSHA,
					FilePath:   content.FileRef.Path,
					LineNumber: lineNum + 1,
					Redacted:   redact(secretVal),
					Confidence: confidence,
					Tags:       rule.Tags,
					Timestamp:  content.Event.Timestamp,
				}
				// Stamp the stable fingerprint so it appears in every sink's
				// output — operators copy it into a --suppress-file to silence a
				// known false positive, and it is the cross-run dedup key.
				finding.Fingerprint = Fingerprint(finding)

				// Cross-run dedup / re-leak suppression: an alerting tool without
				// dedup is a spam cannon. If the suppressor has seen this exact
				// finding before (this run or a prior one) or it is on an operator
				// suppress-list, count it and skip every sink — never re-alert.
				if e.suppressor != nil {
					if e.suppressor.Suppress(finding.Fingerprint) {
						atomic.AddUint64(&e.suppressed, 1)
						continue
					}
					e.suppressor.MarkSeen(finding.Fingerprint)
				}

				for _, sink := range e.sinks {
					if err := sink.Emit(ctx, finding); err != nil {
						return total, err
					}
				}
				total++
			}
		}
	}
	return total, nil
}

// extractSecret returns the value of the capture group at index secretGroup
// from the submatch slice. If secretGroup is 0 or out of range, the full
// match (submatch[0]) is returned instead.
func extractSecret(submatch []string, secretGroup int) string {
	if secretGroup > 0 && secretGroup < len(submatch) {
		if submatch[secretGroup] != "" {
			return submatch[secretGroup]
		}
	}
	return submatch[0]
}

// computeConfidence returns a confidence score in [0.0, 1.0] for a match.
//
// Scoring model:
//   - baseConfidence (0.80) for any match that survives keyword + regex + allowlist
//   - +highSpecificityBonus (0.10) if the rule has high-specificity keywords
//     (prefix-pattern rules like AKIA, ghp_, xoxb-)
//   - +entropyConfidenceBonus (0–0.15) based on how far entropy exceeds the
//     rule's minimum threshold (only if rule.Entropy > 0)
//   - Capped at 1.0
func computeConfidence(rule ruleset.Rule, secretVal, filePath string) float64 {
	score := baseConfidence

	// High-specificity bonus: rules with short, unique prefix keywords
	// (length ≤ 6) are tightly constrained and rarely match false positives.
	for _, kw := range rule.Keywords {
		if len(kw) >= 4 && len(kw) <= 8 {
			score += highSpecificityBonus
			break
		}
	}

	// Entropy headroom bonus.
	if rule.Entropy > 0 {
		measured := shannonEntropy(secretVal)
		score += entropyConfidenceBonus(measured, rule.Entropy)
	}

	// Path penalty: generic rules on non-suspicious paths get a small penalty.
	if isGenericRule(rule) && !isSuspiciousPath(filePath) {
		score -= 0.10
	}

	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}
	return score
}

// isGenericRule returns true for rules tagged "generic" — these cast a wider
// net and have higher false-positive risk than provider-specific rules.
func isGenericRule(rule ruleset.Rule) bool {
	for _, tag := range rule.Tags {
		if tag == "generic" {
			return true
		}
	}
	return false
}

// suspiciousPathSegments are path components that strongly suggest credential
// material. Used to penalise generic rules only on non-suspicious paths.
var suspiciousPathSegments = []string{
	".env", "secret", "credential", "config", "token", "key", "auth",
	".aws", ".ssh", "password", "passwd", "htpasswd", "vault",
}

func isSuspiciousPath(path string) bool {
	lower := strings.ToLower(path)
	for _, seg := range suspiciousPathSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

func keywordMatch(s string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// isAllowListed reports whether a matched value is suppressed by the rule's
// value-scoped allowlist axes: literal stopwords or value regexes. The
// gitleaks-standard `regexes` axis (previously parsed but ignored) lets a rule
// author silence a whole shape of false positive — e.g. any AWS key ending in
// EXAMPLE — without listing every literal. A malformed allowlist regex is
// skipped, not treated as a match, so a typo can never silently disable
// detection.
func isAllowListed(match string, al ruleset.AllowList) bool {
	for _, sw := range al.StopWords {
		if strings.Contains(match, sw) {
			return true
		}
	}
	for _, pat := range al.Regexes {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		if re.MatchString(match) {
			return true
		}
	}
	return false
}

// pathAllowListed reports whether the file path matches any of the rule's
// allowlist path regexes (gitleaks `paths`). A matching path suppresses every
// finding the rule would produce in that file — the standard way to exempt
// test fixtures, vendored dirs, or documentation from a noisy rule. Malformed
// patterns are skipped so a typo cannot disable the rule.
func pathAllowListed(path string, patterns []string) bool {
	for _, pat := range patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// commitAllowListed reports whether the commit SHA is on the rule's allowlist
// (gitleaks `commits`) — an operator's "this commit was reviewed, its matches
// are accepted" list. Matching is prefix-tolerant and case-insensitive: an
// allowlist entry that is a prefix of the commit SHA (e.g. a short 8-char SHA
// listed against a full 40-char one) matches, mirroring how Git itself accepts
// abbreviated SHAs. Empty allowlist entries never match.
func commitAllowListed(sha string, commits []string) bool {
	if sha == "" {
		return false
	}
	lower := strings.ToLower(sha)
	for _, c := range commits {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if strings.HasPrefix(lower, c) {
			return true
		}
	}
	return false
}
