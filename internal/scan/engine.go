// Package scan runs the signature engine over fetched file content.
package scan

import (
	"context"
	"regexp"
	"strings"

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
type Engine struct {
	rules []ruleset.Rule
	sinks []output.Sink
}

// New constructs an Engine with the given rules and output sinks.
func New(rules []ruleset.Rule, sinks ...output.Sink) *Engine {
	return &Engine{rules: rules, sinks: sinks}
}

// Scan runs all rules against content and emits Findings to all sinks.
// Returns the number of findings emitted.
func (e *Engine) Scan(ctx context.Context, content fetch.FileContent) (int, error) {
	if content.Skipped {
		return 0, nil
	}
	total := 0
	for _, rule := range e.rules {
		if !keywordMatch(content.Patch, rule.Keywords) {
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

				confidence := computeConfidence(rule, secretVal, content.FileRef.Path)

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

func isAllowListed(match string, al ruleset.AllowList) bool {
	for _, sw := range al.StopWords {
		if strings.Contains(match, sw) {
			return true
		}
	}
	return false
}
