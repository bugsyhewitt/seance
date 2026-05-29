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

	// includeTags, when non-empty, restricts output to findings carrying at least
	// one of these tags — every finding without a listed tag is dropped before the
	// sink fan-out. excludeTags drops any finding carrying at least one of these
	// tags. Both are matched case-insensitively against the finding's rule tags.
	// Exclude wins over include when a tag appears on both lists. Empty lists (the
	// default) impose no tag filtering, leaving behavior unchanged. Both are fixed
	// for the life of the engine. This is the categorical complement to the numeric
	// minConfidence floor: confidence trades recall for precision by score, the tag
	// filter trades it by credential class.
	includeTags map[string]struct{}
	excludeTags map[string]struct{}

	// tagFiltered counts candidate findings dropped by the include/exclude tag
	// filter. Read atomically for the findings_tag_filtered_total metric.
	tagFiltered uint64

	// outputLimit, when > 0, caps the total number of findings the engine emits
	// to its sinks in this run. Once the cap is reached every additional finding
	// is dropped before the sink fan-out (the same precondition the dedup,
	// confidence-floor, and tag-filter drops use), counted in droppedAfterLimit,
	// and onLimitReached is fired exactly once so the pipeline can begin a clean
	// shutdown (drain sinks, persist state, exit 0). Zero (the default) imposes
	// no cap — byte-for-byte the prior behaviour. Fixed for the life of the
	// engine; intended use is one WithOutputLimit call at construction.
	outputLimit int64

	// emittedCount is the running tally of findings actually emitted to the sinks
	// (post every filter and the suppressor). It is the value compared against
	// outputLimit. Read atomically; even with no cap configured it is updated so
	// tests and metrics can sanity-check engine throughput.
	emittedCount uint64

	// droppedAfterLimit counts findings dropped because outputLimit was already
	// reached. Read atomically for the findings_after_limit_total metric. Stays
	// at zero unless OutputLimit is configured.
	droppedAfterLimit uint64

	// onLimitReached is invoked exactly once, the moment the outputLimit cap is
	// reached. The pipeline wires this to its context-cancel function so a
	// limit-reached run begins a clean shutdown the same way a SIGINT does: the
	// in-flight scan completes, every sink's Close is honoured (so a buffered
	// SARIF document is still written and the webhook queue is still drained),
	// and state is persisted. limitFired guards the single-firing invariant.
	onLimitReached func()
	limitFired     uint32
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

// WithTagFilter returns the engine with a categorical tag filter installed.
//
// include, when non-empty, admits only findings whose rule carries at least one
// of the listed tags; every other finding is dropped before the dedup/sink
// fan-out, so every configured sink — stdout, file, SARIF, TUI, and webhook —
// sees only the selected credential classes. exclude drops any finding whose
// rule carries at least one of the listed tags. When both lists name the same
// tag, exclude wins (a finding carrying it is dropped). Matching is
// case-insensitive and tags are trimmed of surrounding whitespace; empty entries
// are ignored. Passing two empty lists (the default) imposes no tag filtering,
// leaving behavior byte-for-byte unchanged. Intended to be called once at
// construction, before Scan runs. The tag filter is applied after the
// minConfidence floor and before fingerprinting/dedup, so a tag-dropped finding
// never reaches any sink and never consumes a dedup slot.
func (e *Engine) WithTagFilter(include, exclude []string) *Engine {
	e.includeTags = normalizeTagSet(include)
	e.excludeTags = normalizeTagSet(exclude)
	return e
}

// normalizeTagSet lower-cases, trims, and de-duplicates a tag list into a set,
// dropping empty entries. Returns nil for an effectively-empty input so callers
// can cheaply test "no filter" with a len()==0 / nil check.
func normalizeTagSet(tags []string) map[string]struct{} {
	if len(tags) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		set[t] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// tagFilterDrops reports whether a finding's tags cause it to be dropped by the
// configured include/exclude tag filter. A finding is dropped when (a) an exclude
// set is configured and the finding carries any excluded tag, or (b) an include
// set is configured and the finding carries none of the included tags. With both
// sets empty nothing is ever dropped.
func (e *Engine) tagFilterDrops(tags []string) bool {
	if len(e.excludeTags) > 0 {
		for _, t := range tags {
			if _, bad := e.excludeTags[strings.ToLower(strings.TrimSpace(t))]; bad {
				return true
			}
		}
	}
	if len(e.includeTags) > 0 {
		for _, t := range tags {
			if _, ok := e.includeTags[strings.ToLower(strings.TrimSpace(t))]; ok {
				return false
			}
		}
		return true
	}
	return false
}

// WithOutputLimit returns the engine with a global cap on the number of
// findings it will emit to its sinks in this run. When limit > 0 the engine
// counts every finding that reaches the sink fan-out (after the confidence
// floor, tag filter, placeholder filter, and suppressor) and, the moment that
// tally hits the cap, fires onReached exactly once. The pipeline wires
// onReached to its context-cancel so a limit-reached run begins a clean
// shutdown — every sink's Close runs, the SARIF document is written, the
// webhook queue is drained, and state is persisted — the same exit path as a
// SIGINT. Subsequent findings are dropped before any sink sees them and counted
// in DroppedAfterLimitCount so the suppression is observable.
//
// limit <= 0 imposes no cap; onReached is never called and behavior is
// byte-for-byte unchanged. A nil onReached is accepted (the cap still drops
// excess findings; only the shutdown signal is omitted) so the limit feature is
// useful even in tests or callers that prefer to discover the cap by polling
// DroppedAfterLimitCount. Intended to be called once at construction, before
// Scan runs.
func (e *Engine) WithOutputLimit(limit int, onReached func()) *Engine {
	if limit < 0 {
		limit = 0
	}
	e.outputLimit = int64(limit)
	e.onLimitReached = onReached
	return e
}

// EmittedCount returns the cumulative number of findings the engine has emitted
// to its sinks (post every filter and the suppressor). Exposed mostly for tests
// and the output-limit machinery; the per-sink counters are the operator-facing
// numbers.
func (e *Engine) EmittedCount() uint64 {
	return atomic.LoadUint64(&e.emittedCount)
}

// DroppedAfterLimitCount returns the cumulative number of findings dropped
// because the configured --output-limit cap was already reached. Used for the
// findings_after_limit_total metric. Stays at zero unless OutputLimit is set.
func (e *Engine) DroppedAfterLimitCount() uint64 {
	return atomic.LoadUint64(&e.droppedAfterLimit)
}

// SuppressedCount returns the cumulative number of findings dropped by the
// suppressor. Used for the findings_suppressed_total metric.
func (e *Engine) SuppressedCount() uint64 {
	return atomic.LoadUint64(&e.suppressed)
}

// TagFilteredCount returns the cumulative number of findings dropped by the
// include/exclude tag filter. Used for the findings_tag_filtered_total metric.
func (e *Engine) TagFilteredCount() uint64 {
	return atomic.LoadUint64(&e.tagFiltered)
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

// fireLimitReached invokes onLimitReached at most once for the life of the
// engine. Guarded by a CAS on limitFired so concurrent emit/drop sites racing
// against each other cannot double-fire the shutdown signal. A nil callback is
// tolerated (the CAS still flips, so a later WithOutputLimit-with-callback
// instance cannot retroactively fire either, but in practice WithOutputLimit is
// called once at construction).
func (e *Engine) fireLimitReached() {
	if atomic.CompareAndSwapUint32(&e.limitFired, 0, 1) {
		if e.onLimitReached != nil {
			e.onLimitReached()
		}
	}
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

				// Categorical tag filter (--tag / --exclude-tag): admit only the
				// credential classes the operator cares about (or drop classes they
				// don't), evaluated on the rule's tags before fingerprinting and the
				// sink fan-out — so a filtered finding never reaches ANY sink and never
				// consumes a dedup slot. With no tag lists configured this is a no-op.
				// It is the categorical complement to the numeric --min-confidence
				// floor and composes with it: a finding must clear both gates to emit.
				if e.tagFilterDrops(rule.Tags) {
					atomic.AddUint64(&e.tagFiltered, 1)
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

				// Global output limit (--output-limit). Once the configured cap is
				// reached, every additional finding is dropped before the sink
				// fan-out — so every sink (stdout, file, SARIF, TUI, webhook) sees
				// exactly the same first N findings and a downstream consumer cannot
				// disagree with the SARIF report. The first drop fires the pipeline's
				// shutdown signal exactly once so the run exits cleanly through the
				// usual Close/drain/persist path. With outputLimit == 0 the check is a
				// single load-and-compare, leaving the unconfigured path unchanged.
				if e.outputLimit > 0 {
					if int64(atomic.LoadUint64(&e.emittedCount)) >= e.outputLimit {
						atomic.AddUint64(&e.droppedAfterLimit, 1)
						e.fireLimitReached()
						continue
					}
				}

				for _, sink := range e.sinks {
					if err := sink.Emit(ctx, finding); err != nil {
						return total, err
					}
				}
				atomic.AddUint64(&e.emittedCount, 1)
				total++

				// If this emission brought us to the cap, fire the shutdown signal
				// immediately — without it the run would only react on the *next*
				// finding (which might never arrive on a quiet feed). The fire is
				// idempotent so a concurrent drop path racing with this emit cannot
				// double-fire.
				if e.outputLimit > 0 && int64(atomic.LoadUint64(&e.emittedCount)) >= e.outputLimit {
					e.fireLimitReached()
				}
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
//   - the rule's own Confidence (if set in (0.0, 1.0]), else baseConfidence
//     (0.80), is the starting score — a per-rule dial a rule author sets in TOML
//     to make a high-trust rule score higher or a noisy rule lower, no code change
//   - +highSpecificityBonus (0.10) if the rule has high-specificity keywords
//     (prefix-pattern rules like AKIA, ghp_, xoxb-)
//   - +entropyConfidenceBonus (0–0.15) based on how far entropy exceeds the
//     rule's minimum threshold (only if rule.Entropy > 0)
//   - −0.10 path penalty for a generic rule on a non-suspicious path
//   - Clamped to [0.0, 1.0]
func computeConfidence(rule ruleset.Rule, secretVal, filePath string) float64 {
	score := ruleBaseConfidence(rule)

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

// ruleBaseConfidence returns the starting confidence for a rule: the rule's own
// Confidence when it is a sane override in (0.0, 1.0], else the engine default
// baseConfidence (0.80). A rule that declares confidence = 0 (the default) or an
// out-of-range value falls back to the engine default, so a malformed override
// never silently disables a rule — Validate flags the out-of-range case at edit
// time, while the engine stays fail-safe at runtime.
func ruleBaseConfidence(rule ruleset.Rule) float64 {
	if rule.Confidence > 0 && rule.Confidence <= 1.0 {
		return rule.Confidence
	}
	return baseConfidence
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
