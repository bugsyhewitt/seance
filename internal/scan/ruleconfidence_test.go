package scan_test

import (
	"context"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// A generic rule on a non-suspicious path: with no per-rule override it scores
// baseConfidence (0.80) − the generic-on-non-suspicious path penalty (0.10) =
// 0.70. Its keyword "secret-token" is longer than 8 chars, so no specificity
// bonus. The per-rule confidence override lets an author re-base it without
// touching engine code; the path penalty then applies on top of the new base.
func genericRuleWithConfidence(conf float64) []ruleset.Rule {
	return []ruleset.Rule{{
		ID:         "generic-secret",
		Regex:      `secret-token-[A-Za-z0-9]{20}`,
		Keywords:   []string{"secret-token"},
		Tags:       []string{"generic"},
		Confidence: conf,
	}}
}

const genericLine = "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn"

// scanOne runs a single-line scan of the given rules on a non-suspicious path
// and returns the (single) emitted finding. It fails the test if exactly one
// finding is not produced.
func scanOne(t *testing.T, rules []ruleset.Rule) output.Finding {
	t.Helper()
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	n, err := engine.Scan(context.Background(), newContentAt("README.md", "abc123", genericLine, []string{genericLine}))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got n=%d sink=%d", n, len(findings))
	}
	return findings[0]
}

// TestEngine_RuleConfidence_DefaultUnchanged verifies that a rule with no
// confidence override (the zero value) scores exactly as before: 0.70 for this
// generic-on-non-suspicious-path rule. This pins the no-override path to its
// prior, byte-for-byte behavior.
func TestEngine_RuleConfidence_DefaultUnchanged(t *testing.T) {
	got := scanOne(t, genericRuleWithConfidence(0)).Confidence
	if want := 0.70; !approx(got, want) {
		t.Errorf("default (no override) confidence: got %.4f, want %.4f", got, want)
	}
}

// TestEngine_RuleConfidence_OverrideRaisesBase verifies a higher per-rule base
// lifts the final score. With base 0.95 and the 0.10 generic path penalty, the
// finding scores 0.85 — above where the same rule would land on the default base.
func TestEngine_RuleConfidence_OverrideRaisesBase(t *testing.T) {
	got := scanOne(t, genericRuleWithConfidence(0.95)).Confidence
	if want := 0.85; !approx(got, want) {
		t.Errorf("raised-base confidence: got %.4f, want %.4f", got, want)
	}
}

// TestEngine_RuleConfidence_OverrideLowersBase verifies a lower per-rule base
// drops the final score. With base 0.50 and the 0.10 penalty, the finding scores
// 0.40 — the dial a noisy generic rule's author reaches for.
func TestEngine_RuleConfidence_OverrideLowersBase(t *testing.T) {
	got := scanOne(t, genericRuleWithConfidence(0.50)).Confidence
	if want := 0.40; !approx(got, want) {
		t.Errorf("lowered-base confidence: got %.4f, want %.4f", got, want)
	}
}

// TestEngine_RuleConfidence_ClampedAtOne verifies the final score never exceeds
// 1.0 even when a high override plus bonuses would overflow. A prefix rule with
// override 1.0 plus the 0.10 specificity bonus clamps to 1.0, not 1.10.
func TestEngine_RuleConfidence_ClampedAtOne(t *testing.T) {
	rules := []ruleset.Rule{{
		ID:         "aws-access-key-id",
		Regex:      `AKIA[A-Z0-9]{16}`,
		Keywords:   []string{"AKIA"}, // 4 chars → specificity bonus applies
		Confidence: 1.0,
	}}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	line := "AKIA2E4F6H8J0L2N4P6R"
	if _, err := engine.Scan(context.Background(), newContentAt("README.md", "abc123", line, []string{line})); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if got := findings[0].Confidence; got != 1.0 {
		t.Errorf("override 1.0 + specificity bonus must clamp to 1.0, got %.4f", got)
	}
}

// TestEngine_RuleConfidence_OutOfRangeFallsBackToDefault verifies the engine is
// fail-safe: an out-of-range override (negative, or >1.0) is ignored and the rule
// scores on the engine default base, exactly as if no override were set. Validate
// flags the mistake at edit time; the engine never silently breaks detection.
func TestEngine_RuleConfidence_OutOfRangeFallsBackToDefault(t *testing.T) {
	for _, bad := range []float64{-0.5, 1.5} {
		got := scanOne(t, genericRuleWithConfidence(bad)).Confidence
		if want := 0.70; !approx(got, want) {
			t.Errorf("out-of-range override %.2f should fall back to default 0.70, got %.4f", bad, got)
		}
	}
}

// TestEngine_RuleConfidence_ComposesWithMinConfidence verifies a per-rule override
// composes with the global --min-confidence floor: a rule re-based low enough to
// fall below the floor is dropped, while the same rule at its default base passes.
func TestEngine_RuleConfidence_ComposesWithMinConfidence(t *testing.T) {
	// Default base 0.70 ≥ floor 0.65 → emitted.
	var keep []output.Finding
	keepEngine := scan.New(genericRuleWithConfidence(0), &captureSink{findings: &keep}).WithMinConfidence(0.65)
	if n, _ := keepEngine.Scan(context.Background(), newContentAt("README.md", "abc123", genericLine, []string{genericLine})); n != 1 {
		t.Errorf("default-base finding at 0.70 should clear a 0.65 floor, got %d emitted", n)
	}

	// Re-based to 0.50 → final 0.40 < floor 0.65 → dropped.
	var drop []output.Finding
	dropEngine := scan.New(genericRuleWithConfidence(0.50), &captureSink{findings: &drop}).WithMinConfidence(0.65)
	if n, _ := dropEngine.Scan(context.Background(), newContentAt("README.md", "abc123", genericLine, []string{genericLine})); n != 0 {
		t.Errorf("re-based 0.40 finding should be dropped by a 0.65 floor, got %d emitted", n)
	}
	if got := dropEngine.BelowConfidenceCount(); got != 1 {
		t.Errorf("below-confidence counter: got %d, want 1", got)
	}
}

// approx reports whether two confidence scores are equal within float tolerance.
func approx(a, b float64) bool {
	const eps = 1e-9
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < eps
}
