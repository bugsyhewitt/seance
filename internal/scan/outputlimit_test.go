package scan_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// limitTestRule is a high-specificity AWS-style rule that emits one finding per
// matching line. Tests below build a single FileContent carrying many such
// lines, so a configured --output-limit can be observed cleanly without any
// cross-rule or cross-file interaction.
func limitTestRule() []ruleset.Rule {
	return []ruleset.Rule{{
		ID:       "aws-access-key-id",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}
}

// linesOf returns n distinct AKIA-shaped lines so each line produces exactly
// one unique finding (distinct fingerprints — the suppressor never collapses
// them, so the cap is what governs how many survive).
func linesOf(n int) []string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]string, n)
	for i := 0; i < n; i++ {
		// 16 chars after AKIA, varied per line.
		var b strings.Builder
		b.WriteString("AKIA")
		for j := 0; j < 16; j++ {
			b.WriteByte(alpha[(i*16+j)%len(alpha)])
		}
		out[i] = b.String()
	}
	return out
}

// TestEngine_OutputLimit_CapsEmittedFindings verifies the cap is strictly
// enforced: a Scan that would naturally emit 10 findings emits exactly 3 when
// --output-limit=3, and the seven dropped findings increment the
// findings_after_limit_total counter.
func TestEngine_OutputLimit_CapsEmittedFindings(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(limitTestRule(), &captureSink{findings: &findings}).
		WithOutputLimit(3, nil)

	lines := linesOf(10)
	content := newContent(strings.Join(lines, "\n"), lines)

	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("output-limit=3 must emit exactly 3 findings, got %d", len(findings))
	}
	if got := engine.EmittedCount(); got != 3 {
		t.Errorf("EmittedCount=%d, want 3", got)
	}
	if got := engine.DroppedAfterLimitCount(); got != 7 {
		t.Errorf("DroppedAfterLimitCount=%d, want 7 (10 candidates - 3 emitted)", got)
	}
}

// TestEngine_OutputLimit_FiresCallbackExactlyOnce verifies the onReached hook is
// invoked the moment the cap is reached and never again, even when many further
// candidates would have been dropped.
func TestEngine_OutputLimit_FiresCallbackExactlyOnce(t *testing.T) {
	var fires uint32
	var findings []output.Finding
	engine := scan.New(limitTestRule(), &captureSink{findings: &findings}).
		WithOutputLimit(2, func() { atomic.AddUint32(&fires, 1) })

	lines := linesOf(20)
	content := newContent(strings.Join(lines, "\n"), lines)
	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := atomic.LoadUint32(&fires); got != 1 {
		t.Errorf("onReached callback fired %d time(s), want exactly 1", got)
	}
	if len(findings) != 2 {
		t.Errorf("output-limit=2 must emit exactly 2 findings, got %d", len(findings))
	}
	// Second Scan still respects the (already-reached) cap and does not refire.
	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("Scan (second): %v", err)
	}
	if got := atomic.LoadUint32(&fires); got != 1 {
		t.Errorf("after second Scan, callback fires = %d, want still 1 (idempotent)", got)
	}
	if len(findings) != 2 {
		t.Errorf("after second Scan, total emitted = %d, want still 2 (cap holds across Scans)", len(findings))
	}
}

// TestEngine_OutputLimit_ZeroDisablesCap verifies the default (no cap) leaves
// behavior unchanged: every candidate finding is emitted, the drop counter
// stays at zero, and no callback fires (even if one is somehow passed).
func TestEngine_OutputLimit_ZeroDisablesCap(t *testing.T) {
	var fires uint32
	var findings []output.Finding
	engine := scan.New(limitTestRule(), &captureSink{findings: &findings}).
		WithOutputLimit(0, func() { atomic.AddUint32(&fires, 1) })

	lines := linesOf(5)
	content := newContent(strings.Join(lines, "\n"), lines)
	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 5 {
		t.Errorf("no cap must emit every finding, got %d/5", len(findings))
	}
	if got := engine.DroppedAfterLimitCount(); got != 0 {
		t.Errorf("DroppedAfterLimitCount with no cap = %d, want 0", got)
	}
	if got := atomic.LoadUint32(&fires); got != 0 {
		t.Errorf("no cap must never fire the callback, got %d", got)
	}
}

// TestEngine_OutputLimit_NegativeClampedToZero verifies a negative cap (callers
// catch this at the CLI layer, but the engine is defensively fail-safe) clamps
// to zero — no cap — rather than silently dropping every finding.
func TestEngine_OutputLimit_NegativeClampedToZero(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(limitTestRule(), &captureSink{findings: &findings}).
		WithOutputLimit(-5, nil)

	lines := linesOf(4)
	content := newContent(strings.Join(lines, "\n"), lines)
	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 4 {
		t.Errorf("negative cap must clamp to 0 (unlimited), got %d/4 emitted", len(findings))
	}
	if got := engine.DroppedAfterLimitCount(); got != 0 {
		t.Errorf("clamped-to-0 cap must never increment drop counter, got %d", got)
	}
}

// TestEngine_OutputLimit_FansOutToEverySink verifies the cap applies engine-wide:
// when two sinks are attached, both receive exactly the same first-N findings
// (so a downstream consumer cannot disagree with another about how many findings
// the run produced — the documented invariant the cap exists to guarantee).
func TestEngine_OutputLimit_FansOutToEverySink(t *testing.T) {
	var a, b []output.Finding
	engine := scan.New(limitTestRule(),
		&captureSink{findings: &a},
		&captureSink{findings: &b}).
		WithOutputLimit(2, nil)

	lines := linesOf(6)
	content := newContent(strings.Join(lines, "\n"), lines)
	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("cap must apply equally to every sink: sinkA=%d sinkB=%d (want 2 each)", len(a), len(b))
	}
	// Both sinks must see the SAME first two findings (in the same order), not a
	// disjoint pair — otherwise the report a security platform ingests via SARIF
	// could disagree with the stdout NDJSON about which findings the run kept.
	for i := range a {
		if a[i].Fingerprint != b[i].Fingerprint {
			t.Errorf("sink fan-out divergence at i=%d: a=%s b=%s", i, a[i].Fingerprint, b[i].Fingerprint)
		}
	}
}
