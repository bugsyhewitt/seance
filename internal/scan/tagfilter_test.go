package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// awsTaggedRule fires on an AKIA key and carries the "aws" tag. Its keyword
// "AKIA" is 4 chars (specificity bonus), so the finding scores 0.90 — well above
// any default floor — keeping these tests about tags, not confidence.
func awsTaggedRule() []ruleset.Rule {
	return []ruleset.Rule{{
		ID:       "aws-access-key-id",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
		Tags:     []string{"aws", "cloud"},
	}}
}

// genericTaggedRule fires on a generic token and carries the "generic" tag. Its
// content is placed on a suspicious path (.env via newContent) so the
// generic-on-non-suspicious-path penalty does NOT apply and the finding clears a
// default-zero floor — again isolating tag behavior from confidence.
func genericTaggedRule() []ruleset.Rule {
	return []ruleset.Rule{{
		ID:       "generic-secret",
		Regex:    `secret-token-[A-Za-z0-9]{20}`,
		Keywords: []string{"secret-token"},
		Tags:     []string{"generic"},
	}}
}

const tagAWSLine = "AKIA2E4F6H8J0L2N4P6R"
const tagGenericLine = "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn"

// TestEngine_TagFilter_IncludeAdmitsMatching verifies that with an include list,
// a finding whose rule carries a listed tag is emitted normally and is not
// counted as a tag-filter drop.
func TestEngine_TagFilter_IncludeAdmitsMatching(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter([]string{"aws"}, nil)

	content := newContent(tagAWSLine, []string{tagAWSLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(findings) != 1 {
		t.Fatalf("included-tag finding must be emitted: n=%d sink=%d", n, len(findings))
	}
	if got := engine.TagFilteredCount(); got != 0 {
		t.Errorf("an admitted finding must not be counted as a tag drop, got %d", got)
	}
}

// TestEngine_TagFilter_IncludeDropsNonMatching verifies that with an include
// list, a finding whose rule carries NONE of the listed tags never reaches any
// sink and increments the tag-filter counter exactly once.
func TestEngine_TagFilter_IncludeDropsNonMatching(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(genericTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter([]string{"aws"}, nil) // the finding is tagged "generic", not "aws"

	content := newContent(tagGenericLine, []string{tagGenericLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 0 || len(findings) != 0 {
		t.Fatalf("non-included finding must be dropped: n=%d sink=%d", n, len(findings))
	}
	if got := engine.TagFilteredCount(); got != 1 {
		t.Errorf("findings_tag_filtered_total: got %d, want 1", got)
	}
}

// TestEngine_TagFilter_ExcludeDropsMatching verifies that with an exclude list, a
// finding whose rule carries a listed tag is dropped and counted, even with no
// include list configured.
func TestEngine_TagFilter_ExcludeDropsMatching(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(genericTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter(nil, []string{"generic"})

	content := newContent(tagGenericLine, []string{tagGenericLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 0 || len(findings) != 0 {
		t.Fatalf("excluded-tag finding must be dropped: n=%d sink=%d", n, len(findings))
	}
	if got := engine.TagFilteredCount(); got != 1 {
		t.Errorf("findings_tag_filtered_total: got %d, want 1", got)
	}
}

// TestEngine_TagFilter_ExcludeAdmitsNonMatching verifies that with an exclude
// list, a finding carrying none of the excluded tags is emitted and not counted.
func TestEngine_TagFilter_ExcludeAdmitsNonMatching(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter(nil, []string{"generic"}) // the finding is tagged "aws"/"cloud"

	content := newContent(tagAWSLine, []string{tagAWSLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(findings) != 1 {
		t.Fatalf("non-excluded finding must be emitted: n=%d sink=%d", n, len(findings))
	}
	if got := engine.TagFilteredCount(); got != 0 {
		t.Errorf("a non-excluded finding must not be counted as a tag drop, got %d", got)
	}
}

// TestEngine_TagFilter_ExcludeWinsOverInclude verifies the documented precedence:
// when a tag appears on both the include and exclude lists, exclude wins and the
// finding is dropped.
func TestEngine_TagFilter_ExcludeWinsOverInclude(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter([]string{"aws"}, []string{"aws"})

	content := newContent(tagAWSLine, []string{tagAWSLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 0 || len(findings) != 0 {
		t.Fatalf("exclude must win over include: n=%d sink=%d", n, len(findings))
	}
	if got := engine.TagFilteredCount(); got != 1 {
		t.Errorf("findings_tag_filtered_total: got %d, want 1", got)
	}
}

// TestEngine_TagFilter_CaseInsensitive verifies matching is case-insensitive and
// trims whitespace on both the operator's list and the rule's tags.
func TestEngine_TagFilter_CaseInsensitive(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter([]string{"  AWS  "}, nil) // rule tag is lowercase "aws"

	content := newContent(tagAWSLine, []string{tagAWSLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(findings) != 1 {
		t.Fatalf("case-insensitive include must admit the finding: n=%d sink=%d", n, len(findings))
	}
}

// TestEngine_TagFilter_NoFilterAdmitsEverything verifies the default (no lists,
// or only empty/whitespace entries) imposes no filtering: behavior is unchanged
// and the counter stays at zero.
func TestEngine_TagFilter_NoFilterAdmitsEverything(t *testing.T) {
	// No WithTagFilter call at all.
	var a []output.Finding
	plain := scan.New(genericTaggedRule(), &captureSink{findings: &a})
	if n, _ := plain.Scan(context.Background(), newContent(tagGenericLine, []string{tagGenericLine})); n != 1 {
		t.Fatalf("with no tag filter the finding must emit, got %d", n)
	}
	if got := plain.TagFilteredCount(); got != 0 {
		t.Errorf("no filter must never increment the tag-filter counter, got %d", got)
	}

	// Lists that are entirely empty/whitespace normalize to no filter.
	var b []output.Finding
	blank := scan.New(genericTaggedRule(), &captureSink{findings: &b}).
		WithTagFilter([]string{"", "  "}, []string{""})
	if n, _ := blank.Scan(context.Background(), newContent(tagGenericLine, []string{tagGenericLine})); n != 1 {
		t.Fatalf("whitespace-only lists must impose no filter, got %d emitted", n)
	}
	if got := blank.TagFilteredCount(); got != 0 {
		t.Errorf("whitespace-only lists must not count drops, got %d", got)
	}
}

// TestEngine_TagFilter_ComposesWithMinConfidence verifies the tag filter and the
// confidence floor are independent gates: a finding must clear BOTH to emit. Here
// the tag passes the include list but the finding sits below the floor, so it is
// dropped by confidence (and is NOT double-counted as a tag drop).
func TestEngine_TagFilter_ComposesWithMinConfidence(t *testing.T) {
	var findings []output.Finding
	// generic rule on a non-suspicious path scores 0.70 (the path penalty applies).
	rule := []ruleset.Rule{{
		ID:       "generic-secret",
		Regex:    `secret-token-[A-Za-z0-9]{20}`,
		Keywords: []string{"secret-token"},
		Tags:     []string{"generic"},
	}}
	engine := scan.New(rule, &captureSink{findings: &findings}).
		WithMinConfidence(0.80).
		WithTagFilter([]string{"generic"}, nil) // tag passes; confidence does not

	content := newContentAt("README.md", "abc123", tagGenericLine, []string{tagGenericLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 0 || len(findings) != 0 {
		t.Fatalf("finding below the floor must be dropped even with a passing tag: n=%d", n)
	}
	// Dropped by confidence (evaluated first), not by the tag filter.
	if got := engine.BelowConfidenceCount(); got != 1 {
		t.Errorf("findings_below_confidence_total: got %d, want 1", got)
	}
	if got := engine.TagFilteredCount(); got != 0 {
		t.Errorf("a confidence-dropped finding must not be counted as a tag drop, got %d", got)
	}
}

// TestEngine_TagFilter_NoRawLeakOnDrop verifies the never-store-raw invariant on
// the tag-filter drop path: a dropped finding produces no sink output at all, so
// no raw secret material can escape through a tag-gated drop.
func TestEngine_TagFilter_NoRawLeakOnDrop(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(genericTaggedRule(), &captureSink{findings: &findings}).
		WithTagFilter([]string{"aws"}, nil) // drops the "generic"-tagged finding

	raw := tagGenericLine
	if _, err := engine.Scan(context.Background(), newContent(raw, []string{raw})); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a tag-dropped finding must emit nothing, got %d", len(findings))
	}
	for _, f := range findings {
		if strings.Contains(f.Redacted, raw) || strings.Contains(f.Fingerprint, raw) {
			t.Errorf("raw secret leaked into a finding: %+v", f)
		}
	}
}
