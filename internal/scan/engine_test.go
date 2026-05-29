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
			ID:       "generic-secret",
			Regex:    `(?i)secret\s*=\s*['"]?([A-Za-z0-9/+=]{32,64})['"]?`,
			Keywords: []string{"secret"},
			Entropy:  3.5,
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
			ID:       "no-entropy-rule",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			Entropy:  0, // disabled
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

// ── Cross-run finding suppression (POST_V01 Item 4) ─────────────────────────────

// memSuppressor is an in-memory scan.Suppressor for engine tests: it suppresses
// any fingerprint in its always-ignore set or already recorded as seen.
type memSuppressor struct {
	always map[string]bool // operator suppress-list analogue
	seen   map[string]bool // recorded via MarkSeen
}

func newMemSuppressor(always ...string) *memSuppressor {
	m := &memSuppressor{always: map[string]bool{}, seen: map[string]bool{}}
	for _, fp := range always {
		m.always[fp] = true
	}
	return m
}

func (m *memSuppressor) Suppress(fp string) bool { return m.always[fp] || m.seen[fp] }
func (m *memSuppressor) MarkSeen(fp string)      { m.seen[fp] = true }

func awsRule() []ruleset.Rule {
	return []ruleset.Rule{{
		ID:       "aws-access-key-id",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}
}

// TestEngine_Suppressor_DuplicateSuppressed verifies that the second scan of an
// identical finding is dropped (not emitted) and counted, while the first passes.
func TestEngine_Suppressor_DuplicateSuppressed(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsRule(), &captureSink{findings: &findings}).
		WithSuppressor(newMemSuppressor())

	line := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	content := newContent(line, []string{line})

	// First sighting: emitted.
	n1, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("scan 1: %v", err)
	}
	if n1 != 1 {
		t.Fatalf("first scan should emit 1 finding, got %d", n1)
	}
	// Second sighting of the same secret in the same repo+file: suppressed.
	n2, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if n2 != 0 {
		t.Errorf("re-detected finding should be suppressed, got %d emitted", n2)
	}
	if len(findings) != 1 {
		t.Errorf("sink should have received exactly 1 finding, got %d", len(findings))
	}
	if got := engine.SuppressedCount(); got != 1 {
		t.Errorf("findings_suppressed_total: got %d, want 1", got)
	}
}

// TestEngine_Suppressor_DistinctNotSuppressed verifies that a genuinely
// different finding (different repo) is not suppressed by a prior one.
func TestEngine_Suppressor_DistinctNotSuppressed(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsRule(), &captureSink{findings: &findings}).
		WithSuppressor(newMemSuppressor())

	line := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

	c1 := newContent(line, []string{line}) // repo "alice/repo" via newContent default
	c2 := newContent(line, []string{line})
	c2.Event.RepoOwner = "bob" // distinct location → distinct fingerprint

	n1, _ := engine.Scan(context.Background(), c1)
	n2, _ := engine.Scan(context.Background(), c2)
	if n1 != 1 || n2 != 1 {
		t.Errorf("distinct findings should both emit: got n1=%d n2=%d", n1, n2)
	}
	if engine.SuppressedCount() != 0 {
		t.Errorf("no finding should have been suppressed, got %d", engine.SuppressedCount())
	}
}

// TestEngine_Suppressor_SuppressListHonored verifies that a finding whose
// fingerprint is on the operator suppress-list is dropped on the very first
// sighting (never alerted), and counted.
func TestEngine_Suppressor_SuppressListHonored(t *testing.T) {
	// First, learn the fingerprint the engine will compute for this finding by
	// scanning once with no suppressor and reading it back from the sink.
	var probe []output.Finding
	probeEngine := scan.New(awsRule(), &captureSink{findings: &probe})
	line := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	if _, err := probeEngine.Scan(context.Background(), newContent(line, []string{line})); err != nil {
		t.Fatalf("probe scan: %v", err)
	}
	if len(probe) != 1 || probe[0].Fingerprint == "" {
		t.Fatalf("probe should yield 1 finding with a fingerprint, got %+v", probe)
	}
	fp := probe[0].Fingerprint

	// Now scan with that fingerprint on the always-ignore list.
	var findings []output.Finding
	engine := scan.New(awsRule(), &captureSink{findings: &findings}).
		WithSuppressor(newMemSuppressor(fp))

	n, err := engine.Scan(context.Background(), newContent(line, []string{line}))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n != 0 || len(findings) != 0 {
		t.Errorf("suppress-listed finding must never reach a sink: n=%d sink=%d", n, len(findings))
	}
	if engine.SuppressedCount() != 1 {
		t.Errorf("findings_suppressed_total: got %d, want 1", engine.SuppressedCount())
	}
}

// TestEngine_Fingerprint_StampedOnFinding verifies that every emitted finding
// carries a non-empty fingerprint matching scan.Fingerprint, so operators can
// copy it straight into a suppress-file.
func TestEngine_Fingerprint_StampedOnFinding(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsRule(), &captureSink{findings: &findings})
	line := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	if _, err := engine.Scan(context.Background(), newContent(line, []string{line})); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	got := findings[0].Fingerprint
	if got == "" {
		t.Fatal("emitted finding must carry a fingerprint")
	}
	if want := scan.Fingerprint(findings[0]); got != want {
		t.Errorf("stamped fingerprint %q must equal scan.Fingerprint %q", got, want)
	}
}

// TestEngine_NoSuppressor_EmitsEverything confirms backward compatibility: with
// no suppressor installed, duplicate scans both emit (legacy behaviour).
func TestEngine_NoSuppressor_EmitsEverything(t *testing.T) {
	var findings []output.Finding
	engine := scan.New(awsRule(), &captureSink{findings: &findings})
	line := "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	content := newContent(line, []string{line})
	n1, _ := engine.Scan(context.Background(), content)
	n2, _ := engine.Scan(context.Background(), content)
	if n1 != 1 || n2 != 1 {
		t.Errorf("without a suppressor every scan emits: got n1=%d n2=%d", n1, n2)
	}
	if engine.SuppressedCount() != 0 {
		t.Errorf("no suppressor means zero suppressed, got %d", engine.SuppressedCount())
	}
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

// ── Allowlist: regexes / paths / commits ─────────────────────────────────────

// newContentAt builds FileContent at a specific file path and commit SHA so the
// path- and commit-scoped allowlist tests can vary those independently of the
// .env / abc123 defaults baked into newContent.
func newContentAt(path, commitSHA, patch string, lines []string) fetch.FileContent {
	return fetch.FileContent{
		Event:   ingestion.CommitEvent{RepoOwner: "alice", RepoName: "repo", CommitSHA: commitSHA},
		FileRef: ingestion.FileRef{Path: path, Status: "added"},
		Patch:   patch,
		Lines:   lines,
	}
}

// TestEngine_AllowList_RegexSuppresses verifies that a match whose secret value
// matches an allowlist regex is dropped — the gitleaks-standard `regexes`
// mechanism, previously parsed but silently ignored.
func TestEngine_AllowList_RegexSuppresses(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				// Any AWS key ending in EXAMPLE is a documented placeholder.
				Regexes: []string{`AKIA[A-Z0-9]{9}EXAMPLE`},
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
		t.Errorf("expected 0 findings (regex-allowlisted), got %d", n)
	}
}

// TestEngine_AllowList_RegexLetsRealKeyThrough verifies the regex allowlist is
// scoped — a real key that does not match the allowlist regex still fires.
func TestEngine_AllowList_RegexLetsRealKeyThrough(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				Regexes: []string{`AKIA[A-Z0-9]{9}EXAMPLE`},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContent(
		"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
		[]string{"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 1 {
		t.Errorf("expected 1 finding (not allowlisted), got %d", n)
	}
}

// TestEngine_AllowList_PathSuppresses verifies that all matches in a file whose
// path matches an allowlist path regex are dropped — the gitleaks `paths`
// mechanism, previously parsed but silently ignored.
func TestEngine_AllowList_PathSuppresses(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				// Test fixtures are allowed to carry sample keys.
				Paths: []string{`(^|/)testdata/`, `_test\.go$`},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContentAt(
		"internal/fetch/testdata/sample.txt", "abc123",
		"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		[]string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 0 {
		t.Errorf("expected 0 findings (path-allowlisted), got %d", n)
	}
}

// TestEngine_AllowList_PathLetsOtherPathsThrough verifies the path allowlist is
// scoped — a non-matching path still fires.
func TestEngine_AllowList_PathLetsOtherPathsThrough(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				Paths: []string{`(^|/)testdata/`},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContentAt(
		"src/config/aws.go", "abc123",
		"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
		[]string{"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 1 {
		t.Errorf("expected 1 finding (path not allowlisted), got %d", n)
	}
}

// TestEngine_AllowList_CommitSuppresses verifies that all matches in a commit
// whose SHA is on the allowlist are dropped — the gitleaks `commits` mechanism,
// previously parsed but silently ignored. SHA matching is prefix-tolerant so a
// short SHA in the allowlist matches a full commit SHA.
func TestEngine_AllowList_CommitSuppresses(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				// Known-vetted commit; its findings are accepted false positives.
				Commits: []string{"deadbeef"},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContentAt(
		".env", "deadbeefcafe0123456789",
		"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		[]string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 0 {
		t.Errorf("expected 0 findings (commit-allowlisted), got %d", n)
	}
}

// TestEngine_AllowList_CommitLetsOtherCommitsThrough verifies the commit
// allowlist is scoped — a different commit still fires.
func TestEngine_AllowList_CommitLetsOtherCommitsThrough(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				Commits: []string{"deadbeef"},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContentAt(
		".env", "feedface00112233445566",
		"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
		[]string{"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 1 {
		t.Errorf("expected 1 finding (commit not allowlisted), got %d", n)
	}
}

// TestEngine_AllowList_InvalidRegexIgnored verifies that an un-compilable
// allowlist regex is skipped rather than crashing or silently suppressing
// everything — a malformed allowlist entry must not nuke detection.
func TestEngine_AllowList_InvalidRegexIgnored(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				Regexes: []string{`(unclosed`},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := newContent(
		"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
		[]string{"+AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"},
	)
	n, _ := engine.Scan(context.Background(), content)
	if n != 1 {
		t.Errorf("expected 1 finding (bad allowlist regex ignored), got %d", n)
	}
}
