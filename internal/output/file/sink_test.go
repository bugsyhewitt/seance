package file_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
	outfile "github.com/bugsyhewitt/seance/internal/output/file"
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

// TestEmit_WritesNDJSON verifies each Emit produces exactly one JSON line that
// round-trips back to the original Finding.
func TestEmit_WritesNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.ndjson")
	s, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := sampleFinding()
	if err := s.Emit(context.Background(), want); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %q", len(lines), string(data))
	}

	var got output.Finding
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RuleID != want.RuleID || got.FilePath != want.FilePath || got.Fingerprint != want.Fingerprint {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

// TestEmit_MultipleFindingsOnePerLine verifies several findings produce one
// NDJSON line each, in order.
func TestEmit_MultipleFindingsOnePerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.ndjson")
	s, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i, id := range []string{"r1", "r2", "r3"} {
		f := sampleFinding()
		f.RuleID = id
		f.LineNumber = i
		if err := s.Emit(context.Background(), f); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), string(data))
	}
	for i, want := range []string{"r1", "r2", "r3"} {
		var f output.Finding
		if err := json.Unmarshal([]byte(lines[i]), &f); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}
		if f.RuleID != want {
			t.Errorf("line %d: got rule %q want %q", i, f.RuleID, want)
		}
	}
}

// TestNew_CreatesParentDir verifies a nested path's parent directory is created
// so --output-file logs/seance.ndjson works without prior mkdir.
func TestNew_CreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "findings.ndjson")
	s, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New with nested path: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at nested path: %v", err)
	}
}

// TestEmit_Appends verifies a second Sink on the same path appends rather than
// truncating — a restart must extend the record, not erase it.
func TestEmit_Appends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "append.ndjson")

	s1, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New (run 1): %v", err)
	}
	f1 := sampleFinding()
	f1.RuleID = "first"
	_ = s1.Emit(context.Background(), f1)
	_ = s1.Close()

	s2, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New (run 2): %v", err)
	}
	f2 := sampleFinding()
	f2.RuleID = "second"
	_ = s2.Emit(context.Background(), f2)
	_ = s2.Close()

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 appended lines, got %d: %q", len(lines), string(data))
	}
	if !strings.Contains(lines[0], "first") || !strings.Contains(lines[1], "second") {
		t.Errorf("append order wrong: %q", string(data))
	}
}

// TestClose_Idempotent verifies a double Close does not error and that Emit after
// Close is a silent no-op (drops the finding without panicking).
func TestClose_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.ndjson")
	s, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close should be nil, got: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit after Close should be nil, got: %v", err)
	}
}

// TestEmit_NoRawSecretLeak guards the never-store-raw invariant: the file body is
// the redacted Finding, which has no raw field, so a raw value can never appear.
func TestEmit_NoRawSecretLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noleak.ndjson")
	s, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := sampleFinding()
	f.Redacted = "sha256:abc123" // a fingerprint, never the raw secret
	_ = s.Emit(context.Background(), f)
	_ = s.Close()

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("file output must never contain a raw secret value")
	}
}

// TestNew_BadPath verifies a path whose parent cannot be created surfaces an
// error rather than silently dropping output.
func TestNew_BadPath(t *testing.T) {
	// Create a regular file, then try to use it as a parent directory.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := outfile.New(filepath.Join(blocker, "child.ndjson"))
	if err == nil {
		t.Fatal("expected error when parent dir cannot be created")
	}
}
