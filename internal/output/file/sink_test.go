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

// lineLen returns the on-disk byte length of one sampleFinding NDJSON line so
// rotation tests can size their byte budgets precisely against real output.
func lineLen(t *testing.T) int64 {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe.ndjson")
	s, err := outfile.New(path)
	if err != nil {
		t.Fatalf("New (probe): %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit (probe): %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close (probe): %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat (probe): %v", err)
	}
	return fi.Size()
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %q: %v", path, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return 0
	}
	return len(strings.Split(trimmed, "\n"))
}

// TestRotation_DisabledByDefault verifies maxBytes <= 0 keeps the append-forever
// behaviour: many findings land in a single file and no rotated generations exist.
func TestRotation_DisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	s, err := outfile.NewWithRotation(path, 0)
	if err != nil {
		t.Fatalf("NewWithRotation: %v", err)
	}
	for i := 0; i < 50; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := countLines(t, path); n != 50 {
		t.Errorf("expected all 50 lines in one file, got %d", n)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("expected no rotated file with rotation disabled, got err=%v", err)
	}
}

// TestRotation_RotatesAtThreshold verifies that with a budget of two lines the
// active file holds at most two findings and a .1 generation is created.
func TestRotation_RotatesAtThreshold(t *testing.T) {
	ll := lineLen(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")

	// Budget = 2 lines. The third Emit would push past it, so it rotates first.
	s, err := outfile.NewWithRotation(path, 2*ll)
	if err != nil {
		t.Fatalf("NewWithRotation: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if n := countLines(t, path); n != 1 {
		t.Errorf("active file: expected 1 line after rotation, got %d", n)
	}
	if n := countLines(t, path+".1"); n != 2 {
		t.Errorf("rotated .1: expected 2 lines, got %d", n)
	}
}

// TestRotation_NoLineSplitNoLoss verifies every emitted finding survives a series
// of rotations exactly once — rotation must never split or drop a line. The total
// across the active file and all retained generations equals the emit count, as
// long as we stay within the retained-generation window.
func TestRotation_NoLineSplitNoLoss(t *testing.T) {
	ll := lineLen(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")

	// 2 lines per file, 8 findings => active + .1 + .2 + .3 (keptGenerations=3),
	// which holds 8 lines total — nothing falls off the retention window yet.
	s, err := outfile.NewWithRotation(path, 2*ll)
	if err != nil {
		t.Fatalf("NewWithRotation: %v", err)
	}
	for i := 0; i < 8; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	total := countLines(t, path)
	for _, g := range []string{".1", ".2", ".3"} {
		total += countLines(t, path+g)
	}
	if total != 8 {
		t.Errorf("expected 8 findings preserved across generations, got %d", total)
	}
	// No fifth generation should ever exist (keptGenerations = 3).
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Errorf("expected no .4 generation, got err=%v", err)
	}
}

// TestRotation_KeepsBoundedGenerations verifies that under sustained pressure the
// oldest generations are discarded, so the file count stays bounded.
func TestRotation_KeepsBoundedGenerations(t *testing.T) {
	ll := lineLen(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")

	// 1 line per file, 20 findings => far more rotations than retained generations.
	s, err := outfile.NewWithRotation(path, ll)
	if err != nil {
		t.Fatalf("NewWithRotation: %v", err)
	}
	for i := 0; i < 20; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// At most the active file + 3 retained generations may exist.
	present := 0
	for _, g := range []string{"", ".1", ".2", ".3"} {
		if _, err := os.Stat(path + g); err == nil {
			present++
		}
	}
	if present == 0 {
		t.Fatal("expected at least the active file to exist")
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Errorf("retention exceeded: a .4 generation exists (err=%v)", err)
	}
	if _, err := os.Stat(path + ".5"); !os.IsNotExist(err) {
		t.Errorf("retention exceeded: a .5 generation exists (err=%v)", err)
	}
}

// TestRotation_OversizedSingleLine verifies a single finding larger than the whole
// budget is still written (never lost to an infinite rotation loop): the first
// line always lands in a fresh empty file regardless of the limit.
func TestRotation_OversizedSingleLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	s, err := outfile.NewWithRotation(path, 1) // 1-byte budget, smaller than any line
	if err != nil {
		t.Fatalf("NewWithRotation: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := countLines(t, path); n != 1 {
		t.Errorf("expected the oversized finding to be written once, got %d lines", n)
	}
}

// TestRotation_SeedsSizeFromExistingFile verifies rotation accounts for bytes
// already on disk from a prior run, not just bytes this process wrote — a sink
// reopened on a near-full file rotates on its first write rather than overshooting.
func TestRotation_SeedsSizeFromExistingFile(t *testing.T) {
	ll := lineLen(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")

	// Run 1: fill the file with 2 lines, no rotation (budget exactly 2 lines).
	s1, err := outfile.NewWithRotation(path, 2*ll)
	if err != nil {
		t.Fatalf("NewWithRotation (run 1): %v", err)
	}
	for i := 0; i < 2; i++ {
		_ = s1.Emit(context.Background(), sampleFinding())
	}
	_ = s1.Close()

	// Run 2: reopen. The file is already at the 2-line budget, so the very first
	// Emit must rotate the existing content aside before writing.
	s2, err := outfile.NewWithRotation(path, 2*ll)
	if err != nil {
		t.Fatalf("NewWithRotation (run 2): %v", err)
	}
	if err := s2.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit (run 2): %v", err)
	}
	_ = s2.Close()

	if n := countLines(t, path); n != 1 {
		t.Errorf("active file: expected 1 line after seeded rotation, got %d", n)
	}
	if n := countLines(t, path+".1"); n != 2 {
		t.Errorf("rotated .1: expected the 2 prior-run lines, got %d", n)
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
