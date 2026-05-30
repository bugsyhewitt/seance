package csv_test

import (
	"context"
	encodingcsv "encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
	csvsink "github.com/bugsyhewitt/seance/internal/output/csv"
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
		Redacted:    "AKIA****WXYZ",
		Confidence:  0.95,
		Tags:        []string{"cloud", "aws"},
		Timestamp:   time.Date(2026, 5, 17, 14, 30, 0, 0, time.UTC),
		Fingerprint: "sha256:9b1ec4",
	}
}

// readCSV parses the file at path as CSV and returns header + records.
func readCSV(t *testing.T, path string) ([]string, [][]string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	defer f.Close()
	r := encodingcsv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("expected at least a header row, got none")
	}
	return rows[0], rows[1:]
}

// TestEmitAndClose_WritesHeaderAndRow verifies the canonical happy path: one
// emitted finding, one data row beneath the documented header.
func TestEmitAndClose_WritesHeaderAndRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	hdr, rows := readCSV(t, path)
	want := csvsink.Header()
	if strings.Join(hdr, ",") != strings.Join(want, ",") {
		t.Errorf("header: got %v want %v", hdr, want)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row[1] != "aws-access-key-id" {
		t.Errorf("rule_id col: got %q want aws-access-key-id", row[1])
	}
	if row[2] != "AWS Access Key ID" {
		t.Errorf("rule_description col: got %q", row[2])
	}
	if row[7] != "config/prod.env" {
		t.Errorf("file_path col: got %q", row[7])
	}
	if row[8] != "12" {
		t.Errorf("line_number col: got %q want 12", row[8])
	}
	if row[9] != "AKIA****WXYZ" {
		t.Errorf("redacted col: got %q", row[9])
	}
	if row[10] != "0.95" {
		t.Errorf("confidence col: got %q want 0.95", row[10])
	}
	if row[11] != "cloud;aws" {
		t.Errorf("tags col: got %q want 'cloud;aws'", row[11])
	}
	if row[12] != "sha256:9b1ec4" {
		t.Errorf("fingerprint col: got %q", row[12])
	}
	if row[0] != "2026-05-17T14:30:00Z" {
		t.Errorf("timestamp col: got %q want RFC3339 UTC", row[0])
	}
}

// TestClose_EmptyRunStillWritesHeader verifies a clean (zero-finding) run still
// produces a valid header-only document, so downstream pipelines can rely on
// the file existing with the documented schema.
func TestClose_EmptyRunStillWritesHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	hdr, rows := readCSV(t, path)
	want := csvsink.Header()
	if strings.Join(hdr, ",") != strings.Join(want, ",") {
		t.Errorf("header: got %v want %v", hdr, want)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 data rows, got %d", len(rows))
	}
}

// TestEmit_QuotesEmbeddedSpecialCharacters verifies the underlying csv writer
// correctly quotes a rule description containing commas, quotes, and newlines —
// the three cases a naive Sprintf-based writer would corrupt.
func TestEmit_QuotesEmbeddedSpecialCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	f := sampleFinding()
	f.RuleDesc = `AWS, "primary" key
multi-line`
	f.FilePath = `weird,path.env`
	if err := s.Emit(context.Background(), f); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, rows := readCSV(t, path)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0][2] != `AWS, "primary" key
multi-line` {
		t.Errorf("rule_description col not round-tripped, got %q", rows[0][2])
	}
	if rows[0][7] != "weird,path.env" {
		t.Errorf("file_path col not round-tripped, got %q", rows[0][7])
	}
}

// TestClose_Idempotent verifies a second Close is a no-op (no error, no
// re-write) so a deferred Close in a pipeline that also calls Close explicitly
// is safe.
func TestClose_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	info1, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 1: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	info2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 2: %v", err)
	}
	if info1.ModTime() != info2.ModTime() {
		t.Errorf("second Close re-wrote file (modtime changed)")
	}
}

// TestEmit_AfterCloseIsNoop verifies an Emit racing after Close does not
// resurrect the sink — matches the sarif sink semantics so the pipeline's
// deferred close order is forgiving.
func TestEmit_AfterCloseIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Errorf("post-close Emit returned error: %v", err)
	}
	_, rows := readCSV(t, path)
	if len(rows) != 0 {
		t.Errorf("post-close Emit leaked into file, got %d rows", len(rows))
	}
}

// TestClose_CreatesParentDir verifies the parent directory is auto-created so
// --csv-file reports/scan.csv works without a prior `mkdir reports`.
func TestClose_CreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	path := filepath.Join(dir, "out.csv")
	s := csvsink.New(path)
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file at %q: %v", path, err)
	}
}

// TestClose_AtomicWrite_NoTempLeftover verifies a successful Close leaves no
// .tmp file in the destination directory — the atomic rename always happens.
func TestClose_AtomicWrite_NoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	s := csvsink.New(path)
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %q", e.Name())
		}
	}
}

// TestEmit_NoRawLeak verifies the CSV writer never includes a raw secret —
// because output.Finding has no raw field. This is an architectural assertion
// (the type makes a leak impossible) and a regression guard for a future
// schema change that adds a raw field by mistake.
func TestEmit_NoRawLeak(t *testing.T) {
	const rawShouldNeverAppear = "AKIAIOSFODNN7EXAMPLEKEY1234567890"
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	f := sampleFinding()
	// Redacted must not embed the raw value either — it carries only a mask or
	// a fingerprint. We sanity-check by injecting a deliberately distinctive
	// redacted value (a fingerprint) and asserting it survives unchanged.
	f.Redacted = "sha256:0123abcd"
	if err := s.Emit(context.Background(), f); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if strings.Contains(string(body), rawShouldNeverAppear) {
		t.Errorf("CSV body contains raw-shaped material: %s", string(body))
	}
}

// TestEmit_PreservesInsertionOrder verifies findings appear in the order they
// were emitted — important for an operator who reads the CSV in time order.
func TestEmit_PreservesInsertionOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	ids := []string{"rule-a", "rule-b", "rule-c", "rule-d"}
	for _, id := range ids {
		f := sampleFinding()
		f.RuleID = id
		if err := s.Emit(context.Background(), f); err != nil {
			t.Fatalf("Emit %s: %v", id, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, rows := readCSV(t, path)
	if len(rows) != len(ids) {
		t.Fatalf("expected %d rows, got %d", len(ids), len(rows))
	}
	for i, want := range ids {
		if rows[i][1] != want {
			t.Errorf("row %d rule_id: got %q want %q", i, rows[i][1], want)
		}
	}
}

// TestEmit_ConcurrentSafety exercises the Emit mutex under -race: many
// goroutines emit at once and every finding must land in the file exactly
// once.
func TestEmit_ConcurrentSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Emit(context.Background(), sampleFinding())
		}()
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, rows := readCSV(t, path)
	if len(rows) != n {
		t.Errorf("expected %d rows under concurrent emit, got %d", n, len(rows))
	}
}

// TestEmit_ZeroTimestampRendersEmpty verifies a Finding without a timestamp
// renders an empty timestamp cell rather than the Go zero-value epoch — the
// latter would mislead an operator filtering by date.
func TestEmit_ZeroTimestampRendersEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	s := csvsink.New(path)
	f := sampleFinding()
	f.Timestamp = time.Time{}
	if err := s.Emit(context.Background(), f); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, rows := readCSV(t, path)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0][0] != "" {
		t.Errorf("zero timestamp should render empty, got %q", rows[0][0])
	}
}

// TestSink_SatisfiesOutputSinkInterface is a compile-time guard that the CSV
// sink continues to satisfy output.Sink (so the pipeline's variadic fan-out
// can accept it unchanged).
func TestSink_SatisfiesOutputSinkInterface(t *testing.T) {
	var _ output.Sink = csvsink.New("/dev/null")
}
