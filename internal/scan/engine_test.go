package scan_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// ── Helpers ────────────────────────────────────────────────────────────────────

type captureSink struct{ findings *[]output.Finding }

func (c *captureSink) Emit(_ context.Context, f output.Finding) error {
	*c.findings = append(*c.findings, f)
	return nil
}
func (c *captureSink) Close() error { return nil }

// lockedSink is a concurrency-safe sink used by the hot-reload race test, where
// many goroutines call Scan (and thus Emit) at once.
type lockedSink struct {
	findings *[]output.Finding
	mu       *sync.Mutex
}

func (l *lockedSink) Emit(_ context.Context, f output.Finding) error {
	l.mu.Lock()
	*l.findings = append(*l.findings, f)
	l.mu.Unlock()
	return nil
}
func (l *lockedSink) Close() error { return nil }

func containsStars(s string) bool {
	for _, c := range s {
		if c == '*' {
			return true
		}
	}
	return false
}

func newContent(patch string, lines []string) fetch.FileContent {
	return fetch.FileContent{
		Event:   ingestion.CommitEvent{RepoOwner: "alice", RepoName: "repo", CommitSHA: "abc123"},
		FileRef: ingestion.FileRef{Path: ".env", Status: "added"},
		Patch:   patch,
		Lines:   lines,
	}
}

// ── Basic detection ────────────────────────────────────────────────────────────

func TestEngine_FindsAWSKey(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:          "aws-access-key-id",
			Description: "AWS Access Key ID",
			Regex:       `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			Keywords:    []string{"AKIA"},
		},
	}

	var findings []output.Finding
	sink := &captureSink{findings: &findings}
	engine := scan.New(rules, sink)

	content := newContent(
		"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
		[]string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	)

	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 finding, got %d", n)
	}
	redacted := findings[0].Redacted
	if redacted == "" {
		t.Error("Redacted must not be empty")
	}
	// AKIAIOSFODNN7EXAMPLE is 20 chars (< minRevealLen=24), so expect fingerprint.
	if !strings.HasPrefix(redacted, "sha256:") && !containsStars(redacted) {
		t.Errorf("expected sha256 fingerprint or starred redaction, got %q", redacted)
	}
	// Must never contain raw secret material.
	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("Redacted must not contain raw secret")
	}
}

func TestEngine_NoFindingsOnAllowList(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `(?:AKIA)[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				StopWords: []string{"AKIAIOSFODNN7EXAMPLE"},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContent(
		"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		[]string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 0 {
		t.Errorf("expected 0 findings (allowlisted), got %d", n)
	}
}

func TestEngine_SkippedContent(t *testing.T) {
	rules := []ruleset.Rule{{ID: "x", Regex: `AKIA[A-Z0-9]{16}`, Keywords: []string{"AKIA"}}}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := fetch.FileContent{Skipped: true}
	n, err := engine.Scan(context.Background(), content)
	if err != nil || n != 0 {
		t.Errorf("skipped content should produce 0 findings: n=%d err=%v", n, err)
	}
}

// ── Entropy filtering ──────────────────────────────────────────────────────────

// TestEngine_EntropyFilter_DropLow verifies that a match whose secret value
// falls below the rule's minimum entropy threshold is dropped entirely.
func TestEngine_EntropyFilter_DropLow(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "generic-secret",
			Regex:    `(?i)secret\s*=\s*['"]?([A-Za-z0-9]{32,64})['"]?`,
			Keywords: []string{"secret"},
			Entropy:  3.5, // require decent randomness
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})

	// Low-entropy value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" (all 'a', entropy ≈ 0)
	lowEntropyLine := `secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	content := newContent(lowEntropyLine, []string{lowEntropyLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 0 {
		t.Errorf("low-entropy match should be filtered: got %d findings", n)
	}
}

// TestEngine_EntropyFilter_KeepHigh verifies that a high-entropy secret passes
// the entropy gate.
func TestEngine_EntropyFilter_KeepHigh(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:      "generic-secret",
			Regex:   `(?i)secret\s*=\s*['"]?([A-Za-z0-9/+=]{32,64})['"]?`,
			Keywords: []string{"secret"},
			Entropy: 3.5,
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})

	// High-entropy value: looks like a real random base64 key
	highEntropyLine := `secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	content := newContent(highEntropyLine, []string{highEntropyLine})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 {
		t.Errorf("high-entropy match should pass entropy gate: got %d findings", n)
	}
}

// TestEngine_EntropyDisabled verifies that when rule.Entropy == 0, the entropy
// gate is not applied and even low-entropy matches are reported.
func TestEngine_EntropyDisabled(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:      "no-entropy-rule",
			Regex:   `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			Entropy: 0, // disabled
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContent(
		"+AKIAIOSFODNN7EXAMPLE",
		[]string{"+AKIAIOSFODNN7EXAMPLE"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 1 {
		t.Errorf("entropy disabled: expected 1 finding, got %d", n)
	}
}

// ── SecretGroup extraction ─────────────────────────────────────────────────────

// TestEngine_SecretGroup_ExtractsCapture verifies that when rule.SecretGroup > 0,
// the engine redacts the capture group, not the entire match.
func TestEngine_SecretGroup_ExtractsCapture(t *testing.T) {
	// Rule captures the secret portion in group 1 (after the key= prefix).
	rules := []ruleset.Rule{
		{
			ID:          "aws-secret-key-group",
			Regex:       `(?i)aws_secret_access_key\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?`,
			Keywords:    []string{"aws_secret_access_key"},
			SecretGroup: 1,
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})

	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	line := "aws_secret_access_key = " + secret
	content := newContent(line, []string{line})

	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 finding, got %d", n)
	}

	// The secret is 40 chars (≥ minRevealLen=24) → first4****last4 format.
	redacted := findings[0].Redacted
	if !containsStars(redacted) {
		t.Errorf("expected starred redaction for 40-char secret, got %q", redacted)
	}
	// Must start with first 4 chars of the secret value "wJal", not "aws_".
	if !strings.HasPrefix(redacted, "wJal") {
		t.Errorf("redacted should start with secret's first 4 chars 'wJal', got %q", redacted)
	}
	if strings.Contains(redacted, secret) {
		t.Error("redacted must not contain raw secret")
	}
}

// ── Confidence scoring ─────────────────────────────────────────────────────────

// TestEngine_Confidence_WithEntropy verifies that entropy rules produce a
// higher confidence score than the base when entropy headroom is present.
func TestEngine_Confidence_WithEntropy(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "entropy-rule",
			Regex:    `(?i)key\s*=\s*['"]?([A-Za-z0-9/+=]{40,64})['"]?`,
			Keywords: []string{"key"},
			Entropy:  3.5,
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})

	// High-entropy key — well above the 3.5 threshold.
	line := `key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY234"`
	content := newContent(line, []string{line})
	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 finding, got %d", n)
	}
	// Should be above the base confidence due to entropy headroom.
	if findings[0].Confidence <= 0.80 {
		t.Errorf("confidence with entropy headroom should exceed base 0.80, got %f", findings[0].Confidence)
	}
	if findings[0].Confidence > 1.0 {
		t.Errorf("confidence must not exceed 1.0, got %f", findings[0].Confidence)
	}
}

// ── Rule hot-reload (SIGHUP machinery) ──────────────────────────────────────────

// TestEngine_ReloadRules_SwapsActiveSet verifies that ReloadRules replaces the
// engine's rule set: a value that matched the old rules no longer matches after
// a reload to a disjoint rule set, and a value matching the new rules now does.
func TestEngine_ReloadRules_SwapsActiveSet(t *testing.T) {
	awsRules := []ruleset.Rule{{
		ID: "aws", Regex: `AKIA[A-Z0-9]{16}`, Keywords: []string{"AKIA"},
	}}
	ghRules := []ruleset.Rule{{
		ID: "ghp", Regex: `ghp_[0-9a-zA-Z]{36}`, Keywords: []string{"ghp_"},
	}}

	var findings []output.Finding
	engine := scan.New(awsRules, &captureSink{findings: &findings})

	if engine.RuleCount() != 1 {
		t.Fatalf("initial rule count: got %d, want 1", engine.RuleCount())
	}

	awsLine := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	n, _ := engine.Scan(context.Background(), newContent(awsLine, []string{awsLine}))
	if n != 1 {
		t.Fatalf("aws rule before reload: got %d findings, want 1", n)
	}

	// Swap to a disjoint rule set.
	engine.ReloadRules(ghRules)
	if engine.RuleCount() != 1 {
		t.Fatalf("post-reload rule count: got %d, want 1", engine.RuleCount())
	}

	// The AWS key no longer matches under the GitHub-only rule set.
	findings = findings[:0]
	n, _ = engine.Scan(context.Background(), newContent(awsLine, []string{awsLine}))
	if n != 0 {
		t.Errorf("aws line after reload to gh-only rules: got %d findings, want 0", n)
	}

	// A GitHub PAT now matches the freshly loaded rule.
	ghLine := "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	n, _ = engine.Scan(context.Background(), newContent(ghLine, []string{ghLine}))
	if n != 1 {
		t.Errorf("gh line after reload: got %d findings, want 1", n)
	}
}

// TestEngine_ReloadRules_Empty verifies that reloading to an empty rule set
// disables detection (no panic, zero findings).
func TestEngine_ReloadRules_Empty(t *testing.T) {
	rules := []ruleset.Rule{{ID: "aws", Regex: `AKIA[A-Z0-9]{16}`, Keywords: []string{"AKIA"}}}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})

	engine.ReloadRules(nil)
	if engine.RuleCount() != 0 {
		t.Fatalf("after empty reload, rule count: got %d, want 0", engine.RuleCount())
	}
	line := "+AKIAIOSFODNN7EXAMPLE"
	n, err := engine.Scan(context.Background(), newContent(line, []string{line}))
	if err != nil {
		t.Fatalf("Scan after empty reload: %v", err)
	}
	if n != 0 {
		t.Errorf("empty rule set should produce 0 findings, got %d", n)
	}
}

// TestEngine_ReloadRules_ConcurrentWithScan exercises the RWMutex guarding the
// rule set: many goroutines Scan while another stream of goroutines reloads.
// Run with -race, this asserts there is no data race between Scan's snapshot and
// ReloadRules' swap.
func TestEngine_ReloadRules_ConcurrentWithScan(t *testing.T) {
	awsRules := []ruleset.Rule{{ID: "aws", Regex: `AKIA[A-Z0-9]{16}`, Keywords: []string{"AKIA"}}}
	ghRules := []ruleset.Rule{{ID: "ghp", Regex: `ghp_[0-9a-zA-Z]{36}`, Keywords: []string{"ghp_"}}}

	var findings []output.Finding
	var mu sync.Mutex
	engine := scan.New(awsRules, &lockedSink{findings: &findings, mu: &mu})

	ctx := context.Background()
	line := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	content := newContent(line, []string{line})

	var wg sync.WaitGroup
	// Scanners.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = engine.Scan(ctx, content)
			}
		}()
	}
	// Reloaders alternating between the two rule sets.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if (id+j)%2 == 0 {
					engine.ReloadRules(awsRules)
				} else {
					engine.ReloadRules(ghRules)
				}
			}
		}(i)
	}
	wg.Wait()
	// No assertion on findings count (it depends on interleaving); the test
	// passes if -race reports no data race and nothing panics.
}

// TestEngine_Confidence_Bounded verifies that confidence never exceeds 1.0.
func TestEngine_Confidence_Bounded(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "high-spec-entropy",
			Regex:    `ghp_[0-9a-zA-Z]{36}`,
			Keywords: []string{"ghp_"},
			Entropy:  3.0,
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	// Real-looking GitHub PAT.
	line := "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	content := newContent(line, []string{line})
	n, _ := engine.Scan(context.Background(), content)
	if n == 1 && findings[0].Confidence > 1.0 {
		t.Errorf("confidence exceeded 1.0: got %f", findings[0].Confidence)
	}
}
