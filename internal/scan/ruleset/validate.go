package ruleset

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Problem is a single validation finding against a ruleset. Severity is either
// "error" (the rule will not work, or will be silently skipped, as deployed) or
// "warning" (the rule loads but is likely to misbehave or be ineffective).
type Problem struct {
	// RuleID is the id of the offending rule, or "" for ruleset-level problems
	// (e.g. duplicate ids, or a problem that cannot be attributed to one rule).
	RuleID string
	// RuleIndex is the zero-based position of the rule in the file, used to
	// locate rules that have no id of their own. -1 for ruleset-level problems.
	RuleIndex int
	// Field names the offending field (e.g. "regex", "allowlist.paths[0]").
	Field string
	// Severity is "error" or "warning".
	Severity string
	// Message is a human-readable description of the problem.
	Message string
}

const (
	// SeverityError marks a problem that makes a rule non-functional or causes
	// it to be silently skipped by the scan engine as deployed.
	SeverityError = "error"
	// SeverityWarning marks a problem that loads but is likely ineffective or a
	// mistake (e.g. a rule that can never fire its keyword pre-scan).
	SeverityWarning = "warning"
)

// String renders a Problem as a single diagnostic line, mirroring the
// file:line-style diagnostics operators expect from a linter.
func (p Problem) String() string {
	loc := p.RuleID
	if loc == "" {
		loc = fmt.Sprintf("rule #%d", p.RuleIndex)
	}
	if p.RuleIndex < 0 {
		loc = "ruleset"
	}
	field := p.Field
	if field != "" {
		field = " " + field
	}
	return fmt.Sprintf("%s: [%s]%s: %s", strings.ToUpper(p.Severity), loc, field, p.Message)
}

// Validate checks a parsed Ruleset for the defects the scan engine would
// silently tolerate at runtime, returning every problem found (errors and
// warnings), sorted by rule index then severity.
//
// The engine's posture is fail-safe by design: a rule with a malformed regex,
// or an allowlist with a malformed pattern, is silently skipped at scan time
// (engine.go: regexp.Compile errors are swallowed). That is the correct runtime
// behaviour — a bad edit must never crash a run-for-days monitor — but it means
// a typo silently disables detection with no signal to the operator. Validate
// is the pre-flight counterpart: it surfaces exactly those defects before the
// ruleset is deployed, so the operator learns at edit time, not from a quiet
// stream of zero findings days later.
//
// Checks performed:
//   - error: a rule has no id (the finding's rule_id would be empty)
//   - error: duplicate rule ids (the second shadows nothing but is ambiguous)
//   - error: a rule has an empty regex (matches nothing useful; engine skips it
//     only after compiling an empty pattern, which matches every position)
//   - error: a rule's regex fails to compile (silently skipped by the engine)
//   - error: an allowlist regexes/paths pattern fails to compile (silently
//     skipped by the engine, so the false positive it meant to suppress fires)
//   - error: secretGroup is negative, or exceeds the regex's capture-group count
//     (the engine would fall back to the full match, redacting too much)
//   - warning: a rule has no keywords (the keyword pre-scan is bypassed, so the
//     regex runs against every line — a performance and false-positive risk the
//     default ruleset always avoids)
//   - warning: a non-empty entropy threshold that is implausibly high (>8.0, the
//     maximum Shannon entropy per byte) — the rule can never emit a finding
//   - warning: a confidence override outside [0.0, 1.0] — the engine ignores it
//     and falls back to the default base, so the author's tuning silently does
//     nothing
func Validate(rs *Ruleset) []Problem {
	var problems []Problem
	seen := make(map[string]int) // rule id -> first index seen

	for i, rule := range rs.Rules {
		ruleID := rule.ID

		// Missing id.
		if strings.TrimSpace(rule.ID) == "" {
			problems = append(problems, Problem{
				RuleID: "", RuleIndex: i, Field: "id", Severity: SeverityError,
				Message: "rule has no id; emitted findings would carry an empty rule_id",
			})
		} else if first, dup := seen[rule.ID]; dup {
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "id", Severity: SeverityError,
				Message: fmt.Sprintf("duplicate rule id (first defined at rule #%d)", first),
			})
		} else {
			seen[rule.ID] = i
		}

		// Regex presence + compilation.
		var groupCount int
		regexValid := false
		switch {
		case strings.TrimSpace(rule.Regex) == "":
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "regex", Severity: SeverityError,
				Message: "regex is empty; the rule cannot match a credential",
			})
		default:
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				problems = append(problems, Problem{
					RuleID: ruleID, RuleIndex: i, Field: "regex", Severity: SeverityError,
					Message: fmt.Sprintf("regex does not compile (the engine silently skips this rule at runtime): %v", err),
				})
			} else {
				groupCount = re.NumSubexp()
				regexValid = true
			}
		}

		// secretGroup bounds.
		switch {
		case rule.SecretGroup < 0:
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "secretGroup", Severity: SeverityError,
				Message: fmt.Sprintf("secretGroup is negative (%d)", rule.SecretGroup),
			})
		case regexValid && rule.SecretGroup > groupCount:
			// groupCount is the number of capture groups; secretGroup indexes
			// submatch[1..groupCount]. A value past that range silently falls
			// back to the full match, redacting more than intended. Only checked
			// when the regex compiled — a bad regex is reported once, above.
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "secretGroup", Severity: SeverityError,
				Message: fmt.Sprintf("secretGroup %d exceeds the regex's %d capture group(s); the engine would fall back to the full match and redact too much", rule.SecretGroup, groupCount),
			})
		}

		// Allowlist pattern compilation (regexes + paths). These are the axes
		// the engine compiles at scan time and silently skips on error.
		for j, pat := range rule.AllowList.Regexes {
			if _, err := regexp.Compile(pat); err != nil {
				problems = append(problems, Problem{
					RuleID: ruleID, RuleIndex: i, Field: fmt.Sprintf("allowlist.regexes[%d]", j), Severity: SeverityError,
					Message: fmt.Sprintf("allowlist regex does not compile (silently skipped, so the false positive it suppresses will fire): %v", err),
				})
			}
		}
		for j, pat := range rule.AllowList.Paths {
			if _, err := regexp.Compile(pat); err != nil {
				problems = append(problems, Problem{
					RuleID: ruleID, RuleIndex: i, Field: fmt.Sprintf("allowlist.paths[%d]", j), Severity: SeverityError,
					Message: fmt.Sprintf("allowlist path pattern does not compile (silently skipped, so the path it exempts will not be exempted): %v", err),
				})
			}
		}

		// No keywords: the engine's keyword pre-scan is bypassed, so the regex
		// runs against every line of every file — a real performance and
		// false-positive hazard. Every rule in the default set has keywords.
		if len(rule.Keywords) == 0 {
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "keywords", Severity: SeverityWarning,
				Message: "rule has no keywords; its regex runs against every line (slower, noisier). Add a cheap literal keyword the secret always contains.",
			})
		}

		// Implausible entropy threshold: Shannon entropy per byte saturates at
		// 8 bits. A threshold above that means the rule can never emit.
		if rule.Entropy > 8.0 {
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "entropy", Severity: SeverityWarning,
				Message: fmt.Sprintf("entropy threshold %.2f exceeds the 8.0-bit per-byte maximum; no value can satisfy it, so the rule never fires", rule.Entropy),
			})
		}

		// Out-of-range confidence override: confidence is a score in [0.0, 1.0].
		// A value outside that range (a negative number, or >1.0) is ignored by
		// the engine — it falls back to the default base — so the author's intended
		// tuning silently does nothing. 0 is the documented "use the default" value
		// and is not flagged. Negative values are the real mistake worth surfacing.
		if rule.Confidence < 0 || rule.Confidence > 1.0 {
			problems = append(problems, Problem{
				RuleID: ruleID, RuleIndex: i, Field: "confidence", Severity: SeverityWarning,
				Message: fmt.Sprintf("confidence %.2f is outside the [0.0, 1.0] range; the engine ignores it and uses the default base score, so this override has no effect", rule.Confidence),
			})
		}
	}

	sort.SliceStable(problems, func(a, b int) bool {
		if problems[a].RuleIndex != problems[b].RuleIndex {
			return problems[a].RuleIndex < problems[b].RuleIndex
		}
		// errors before warnings within the same rule
		return problems[a].Severity == SeverityError && problems[b].Severity != SeverityError
	})

	return problems
}

// HasErrors reports whether any problem in the slice is an error (as opposed to
// a warning). Callers use this to decide process exit status: warnings inform,
// errors fail.
func HasErrors(problems []Problem) bool {
	for _, p := range problems {
		if p.Severity == SeverityError {
			return true
		}
	}
	return false
}
