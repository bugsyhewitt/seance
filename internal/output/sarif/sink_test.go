package sarif_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/output/sarif"
)

func sampleFinding() output.Finding {
	return output.Finding{
		RuleID:      "aws-access-key-id",
		RuleDesc:    "AWS Access Key ID",
		Provider:    "github",
		RepoOwner:   "alice",
		RepoName:    "repo",
		CommitSHA:   "deadbeef",
		FilePath:    "config/prod.env",
		LineNumber:  12,
		Redacted:    "sha256:3f2a1b9c",
		Confidence:  0.95,
		Tags:        []string{"cloud", "aws"},
		Timestamp:   time.Date(2026, 5, 17, 14, 30, 0, 0, time.UTC),
		Fingerprint: "sha256:9b1ec4",
	}
}

// decode reads and parses the SARIF document at path into the loosely-typed map
// the public schema describes, so assertions can probe arbitrary fields.
func decode(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sarif: %v\n%s", err, string(data))
	}
	return doc
}

func firstRun(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("expected at least one run, got %v", doc["runs"])
	}
	return runs[0].(map[string]any)
}

// TestClose_WritesValidSarifDocument verifies the top-level envelope: schema,
// version, a single run, and the tool driver naming séance.
func TestClose_WritesValidSarifDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "0.2.0-test")
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	doc := decode(t, path)
	if doc["version"] != "2.1.0" {
		t.Errorf("version: got %v want 2.1.0", doc["version"])
	}
	if _, ok := doc["$schema"]; !ok {
		t.Error("document must carry a $schema")
	}

	run := firstRun(t, doc)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "seance" {
		t.Errorf("driver name: got %v want seance", driver["name"])
	}
	if driver["version"] != "0.2.0-test" {
		t.Errorf("driver version: got %v want 0.2.0-test", driver["version"])
	}
}

// TestResult_MapsFindingFields verifies a finding becomes a result referencing
// its rule, with the line region, artifact URI, and confidence-derived level.
func TestResult_MapsFindingFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "")
	_ = s.Emit(context.Background(), sampleFinding())
	_ = s.Close()

	run := firstRun(t, decode(t, path))
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0].(map[string]any)

	if res["ruleId"] != "aws-access-key-id" {
		t.Errorf("ruleId: got %v", res["ruleId"])
	}
	if res["level"] != "error" { // confidence 0.95 >= 0.8
		t.Errorf("level: got %v want error", res["level"])
	}

	loc := res["locations"].([]any)[0].(map[string]any)
	phys := loc["physicalLocation"].(map[string]any)
	uri := phys["artifactLocation"].(map[string]any)["uri"].(string)
	if !strings.Contains(uri, "alice/repo") || !strings.Contains(uri, "config/prod.env") {
		t.Errorf("artifact uri missing repo/path: %q", uri)
	}
	region := phys["region"].(map[string]any)
	if int(region["startLine"].(float64)) != 12 {
		t.Errorf("startLine: got %v want 12", region["startLine"])
	}
}

// TestRuleCatalog_DeduplicatesRules verifies repeated rule IDs across findings
// collapse to a single catalog entry, and that each result's ruleIndex points
// into it correctly.
func TestRuleCatalog_DeduplicatesRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "")
	f1 := sampleFinding()
	f2 := sampleFinding()
	f2.FilePath = "other.env"
	f3 := sampleFinding()
	f3.RuleID = "stripe-key"
	f3.RuleDesc = "Stripe API Key"
	for _, f := range []output.Finding{f1, f2, f3} {
		_ = s.Emit(context.Background(), f)
	}
	_ = s.Close()

	run := firstRun(t, decode(t, path))
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 { // aws-access-key-id (x2) collapses, plus stripe-key
		t.Fatalf("expected 2 distinct rules, got %d", len(rules))
	}
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	// The third finding's result must index the second (stripe) rule.
	res3 := results[2].(map[string]any)
	idx := int(res3["ruleIndex"].(float64))
	stripe := rules[idx].(map[string]any)
	if stripe["id"] != "stripe-key" {
		t.Errorf("ruleIndex %d points to %v, want stripe-key", idx, stripe["id"])
	}
}

// TestPartialFingerprints carries the stable dedup identity into SARIF's native
// partialFingerprints, using only redacted/hashed values.
func TestPartialFingerprints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "")
	_ = s.Emit(context.Background(), sampleFinding())
	_ = s.Close()

	run := firstRun(t, decode(t, path))
	res := run["results"].([]any)[0].(map[string]any)
	pf, ok := res["partialFingerprints"].(map[string]any)
	if !ok {
		t.Fatal("expected partialFingerprints on result")
	}
	if pf["seanceFingerprint"] != "sha256:9b1ec4" {
		t.Errorf("fingerprint: got %v", pf["seanceFingerprint"])
	}
}

// TestLevelBuckets verifies the confidence→level mapping at the bucket edges.
func TestLevelBuckets(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0.95, "error"},
		{0.80, "error"},
		{0.79, "warning"},
		{0.50, "warning"},
		{0.49, "note"},
		{0.0, "note"},
	}
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), "out.sarif")
		s := sarif.New(path, "")
		f := sampleFinding()
		f.Confidence = tc.conf
		_ = s.Emit(context.Background(), f)
		_ = s.Close()

		run := firstRun(t, decode(t, path))
		res := run["results"].([]any)[0].(map[string]any)
		if res["level"] != tc.want {
			t.Errorf("confidence %.2f: level %v, want %v", tc.conf, res["level"], tc.want)
		}
	}
}

// TestClose_NoRawSecretLeak guards the never-store-raw invariant: the SARIF body
// is built solely from the redacted Finding, which has no raw field.
func TestClose_NoRawSecretLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "")
	f := sampleFinding()
	f.Redacted = "sha256:abc123"
	_ = s.Emit(context.Background(), f)
	_ = s.Close()

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("SARIF output must never contain a raw secret value")
	}
}

// TestClose_Idempotent verifies a double Close is a no-op and Emit after Close is
// silently dropped (no panic, no error).
func TestClose_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "")
	_ = s.Emit(context.Background(), sampleFinding())
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close should be nil, got: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit after Close should be nil, got: %v", err)
	}
	// The document still reflects only the single pre-Close finding.
	run := firstRun(t, decode(t, path))
	if got := len(run["results"].([]any)); got != 1 {
		t.Errorf("expected 1 result after post-Close Emit, got %d", got)
	}
}

// TestNew_CreatesParentDir verifies a nested output path's parent directory is
// created so --sarif-file reports/scan.sarif works without prior mkdir.
func TestNew_CreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "scan.sarif")
	s := sarif.New(path, "")
	_ = s.Emit(context.Background(), sampleFinding())
	if err := s.Close(); err != nil {
		t.Fatalf("Close with nested path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected sarif at nested path: %v", err)
	}
}

// TestClose_EmptyFindingsStillValid verifies a run with zero findings produces a
// valid empty-results document (a clean scan should still emit a report).
func TestClose_EmptyFindingsStillValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.sarif")
	s := sarif.New(path, "0.2.0")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	run := firstRun(t, decode(t, path))
	results := run["results"].([]any)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 0 {
		t.Errorf("expected empty rule catalog, got %d", len(rules))
	}
}

// TestClose_AtomicNoTempLeftover verifies the temp file used for the atomic write
// does not survive a successful Close.
func TestClose_AtomicNoTempLeftover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	s := sarif.New(path, "")
	_ = s.Emit(context.Background(), sampleFinding())
	_ = s.Close()
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file should not survive Close: %v", err)
	}
}
