package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// highConfidenceRule scores baseConfidence (0.80) + highSpecificityBonus (0.10)
// = 0.90, because its only keyword "AKIA" is 4 chars (in the 4–8 bonus window)
// and the rule is not tagged "generic". No entropy gate, so the score is fixed.
func highConfidenceRule() []ruleset.Rule {
	return []ruleset.Rule{{
		ID:       "aws-access-key-id",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}
}

// lowConfidenceRule scores baseConfidence (0.80) − the generic-on-non-suspicious
// -path penalty (0.10) = 0.70: it is tagged "generic", its keyword "secret-token"
// is longer than 8 chars (no specificity bonus), and the test content lives on a
// non-suspicious path. Used to sit a finding *below* a 0.80 floor.
func lowConfidenceRule() []ruleset.Rule {
	return []ruleset.Rule{{
		ID:       "generic-secret",
		Regex:    `secret-token-[A-Za-z0-9]{20}`,
		Keywords: []string{"secret-token"},
		Tags:     []string{"generic"},
	}}
}

// All tests place content on a non-suspicious path (README.md, via newContentAt)
// so the generic-rule path penalty applies. The default newContent helper uses
// ".env", a suspicious path that would cancel the penalty and lift the generic
// rule's score back to base.

// TestEngine_MinConfidence_DropsBelowFloor verifies a finding whose confidence
// is below the floor never reaches any sink, and increments the
// findings_below_confidence_total counter exactly once.
func TestEngine_MinConfidence_DropsBelowFloor(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(lowConfidenceRule(), &captureSink{findings: &findings}).
		WithMinConfidence(0.80)

	// secret-token-<20 alnum> on a non-suspicious path scores 0.70 < 0.80.
	line := "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn"
	content := newContentAt("README.md", "abc123", line, []string{line})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 0 || len(findings) != 0 {
		t.Fatalf("sub-floor finding must be dropped: n=%d sink=%d", n, len(findings))
	}
	if got := engine.BelowConfidenceCount(); got != 1 {
		t.Errorf("findings_below_confidence_total: got %d, want 1", got)
	}
}

// TestEngine_MinConfidence_KeepsAtOrAboveFloor verifies a finding at or above the
// floor is emitted normally and is not counted as a below-confidence drop.
func TestEngine_MinConfidence_KeepsAtOrAboveFloor(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(highConfidenceRule(), &captureSink{findings: &findings}).
		WithMinConfidence(0.90) // exactly the finding's score — must pass (>=).

	line := "AKIA2E4F6H8J0L2N4P6R"
	content := newContentAt("README.md", "abc123", line, []string{line})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(findings) != 1 {
		t.Fatalf("at-floor finding must be emitted: n=%d sink=%d", n, len(findings))
	}
	if findings[0].Confidence < 0.90 {
		t.Errorf("emitted finding confidence %.2f should be >= 0.90", findings[0].Confidence)
	}
	if got := engine.BelowConfidenceCount(); got != 0 {
		t.Errorf("at-floor finding must not be counted as a drop, got %d", got)
	}
}

// TestEngine_MinConfidence_ZeroAdmitsEverything verifies the default floor of 0
// leaves behavior unchanged: a low-confidence finding is still emitted and the
// drop counter stays at zero.
func TestEngine_MinConfidence_ZeroAdmitsEverything(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(lowConfidenceRule(), &captureSink{findings: &findings}) // no floor

	line := "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn"
	content := newContentAt("README.md", "abc123", line, []string{line})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(findings) != 1 {
		t.Fatalf("with no floor a low-confidence finding must still emit: n=%d sink=%d", n, len(findings))
	}
	if got := engine.BelowConfidenceCount(); got != 0 {
		t.Errorf("no floor must never increment the below-confidence counter, got %d", got)
	}
}

// TestEngine_MinConfidence_Clamped verifies out-of-range thresholds are clamped:
// a value above 1.0 clamps to 1.0 (drops a 0.90 finding), and a negative value
// clamps to 0 (admits everything).
func TestEngine_MinConfidence_Clamped(t *testing.T) {
	// Above 1.0 → clamps to 1.0; a 0.90 finding is below it and is dropped.
	var hiFindings []output.Finding
	hiEngine := scan.New(highConfidenceRule(), &captureSink{findings: &hiFindings}).
		WithMinConfidence(5.0)
	line := "AKIA2E4F6H8J0L2N4P6R"
	if n, _ := hiEngine.Scan(context.Background(), newContentAt("README.md", "abc123", line, []string{line})); n != 0 {
		t.Errorf("threshold clamped to 1.0 should drop a 0.90 finding, got %d emitted", n)
	}
	if got := hiEngine.BelowConfidenceCount(); got != 1 {
		t.Errorf("clamped-to-1.0 floor: below-confidence count got %d, want 1", got)
	}

	// Below 0 → clamps to 0; everything is admitted.
	var loFindings []output.Finding
	loEngine := scan.New(highConfidenceRule(), &captureSink{findings: &loFindings}).
		WithMinConfidence(-2.0)
	if n, _ := loEngine.Scan(context.Background(), newContentAt("README.md", "abc123", line, []string{line})); n != 1 {
		t.Errorf("negative threshold clamped to 0 should admit the finding, got %d emitted", n)
	}
	if got := loEngine.BelowConfidenceCount(); got != 0 {
		t.Errorf("clamped-to-0 floor must not count drops, got %d", got)
	}
}

// TestEngine_MinConfidence_NoRawLeakOnDrop verifies the never-store-raw invariant
// on the floor's drop path: a dropped finding produces no sink output at all, so
// no raw secret material can escape through a confidence-gated drop.
func TestEngine_MinConfidence_NoRawLeakOnDrop(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(lowConfidenceRule(), &captureSink{findings: &findings}).
		WithMinConfidence(0.80)

	raw := "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn"
	if _, err := engine.Scan(context.Background(), newContentAt("README.md", "abc123", raw, []string{raw})); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a confidence-dropped finding must emit nothing, got %d", len(findings))
	}
	// Belt-and-braces: nothing in any captured finding ever carries the raw value.
	for _, f := range findings {
		if strings.Contains(f.Redacted, raw) || strings.Contains(f.Fingerprint, raw) {
			t.Errorf("raw secret leaked into a finding: %+v", f)
		}
	}
}
