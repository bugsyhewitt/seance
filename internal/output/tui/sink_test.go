package tui

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

func finding(rule string, conf float64) output.Finding {
	return output.Finding{
		RuleID:     rule,
		RuleDesc:   rule + " description",
		Provider:   "github",
		RepoOwner:  "octocat",
		RepoName:   "hello-world",
		CommitSHA:  "deadbeef",
		FilePath:   ".env",
		LineNumber: 12,
		Redacted:   "AKIA********************WXYZ",
		Confidence: conf,
		Tags:       []string{"aws"},
		Timestamp:  time.Unix(1700000000, 0).UTC(),
	}
}

// TestEmitNonTTYWritesPlainLines verifies the non-TTY path: no escape sequences,
// one stable grep-friendly line per finding, and that core locator fields appear.
// This is the "pipeline-safe" contract — a redirected stream must never be
// corrupted by terminal control codes.
func TestEmitNonTTYWritesPlainLines(t *testing.T) {
	var buf bytes.Buffer
	s := New(Config{Writer: &buf, TTY: false})

	for _, f := range []output.Finding{
		finding("aws-access-key", 0.92),
		finding("github-pat", 0.71),
	} {
		if err := s.Emit(context.Background(), f); err != nil {
			t.Fatalf("Emit returned error: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("non-TTY output must contain no ANSI escape sequences, got:\n%q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 plain lines, got %d:\n%q", len(lines), out)
	}
	if !strings.Contains(lines[0], "aws-access-key") || !strings.Contains(lines[0], "octocat/hello-world") || !strings.Contains(lines[0], ".env") {
		t.Errorf("first line missing locator fields: %q", lines[0])
	}
	if !strings.Contains(lines[0], "92%") {
		t.Errorf("first line missing confidence percentage: %q", lines[0])
	}
}

// TestEmitTTYRendersColoredFrame smoke-tests the TTY render path: a frame is
// painted with cursor control + color, the finding's fields are present, and the
// header counters update. We render to a buffer (TTY:true) so no real terminal
// is required.
func TestEmitTTYRendersColoredFrame(t *testing.T) {
	var buf bytes.Buffer
	s := New(Config{Writer: &buf, TTY: true})
	// New paints an initial empty frame on a TTY.
	if !strings.Contains(buf.String(), "listening") {
		t.Errorf("expected initial empty-frame banner, got:\n%q", buf.String())
	}

	buf.Reset()
	if err := s.Emit(context.Background(), finding("aws-access-key", 0.92)); err != nil {
		t.Fatalf("Emit error: %v", err)
	}
	frame := buf.String()

	for _, want := range []string{
		clearScreen, cursorHome, // full repaint
		ansiRed,            // 0.92 confidence colors red
		"aws-access-key",   // rule id
		"octocat/hello-wo", // repo (may be truncated)
		"findings=1",       // header counter
		"rules_hit=1",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("rendered frame missing %q\nframe:\n%q", want, frame)
		}
	}
}

// TestRecentRingIsBounded asserts the scrollback ring drops the oldest findings
// once it exceeds MaxRecent, so a long-running feed cannot grow unbounded.
func TestRecentRingIsBounded(t *testing.T) {
	var buf bytes.Buffer
	s := New(Config{Writer: &buf, TTY: true, MaxRecent: 3})

	for i := 0; i < 10; i++ {
		_ = s.Emit(context.Background(), finding("rule", 0.5))
	}

	s.mu.Lock()
	got := len(s.recent)
	total := s.total
	s.mu.Unlock()

	if got != 3 {
		t.Errorf("recent ring should be bounded to 3, got %d", got)
	}
	if total != 10 {
		t.Errorf("total counter should track all 10 findings, got %d", total)
	}
}

// TestConfidenceColorThresholds locks in the high/medium/low color mapping so a
// future tweak to thresholds is a conscious decision, not an accident.
func TestConfidenceColorThresholds(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0.95, ansiRed},
		{0.85, ansiRed},
		{0.84, ansiYellow},
		{0.70, ansiYellow},
		{0.69, ansiGreen},
		{0.10, ansiGreen},
	}
	for _, c := range cases {
		if got := confidenceColor(c.conf); got != c.want {
			t.Errorf("confidenceColor(%.2f) = %q, want %q", c.conf, got, c.want)
		}
	}
}

// TestTruncateRuneSafe verifies truncation counts runes (not bytes) so multibyte
// paths are never split mid-character.
func TestTruncateRuneSafe(t *testing.T) {
	if got := truncate("short", 22); got != "short" {
		t.Errorf("short string should pass through unchanged, got %q", got)
	}
	long := "internal/very/deeply/nested/config/secrets.env"
	got := truncate(long, 20)
	if len([]rune(got)) != 20 {
		t.Errorf("truncated length = %d runes, want 20: %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated string should end with ellipsis, got %q", got)
	}
	// Multibyte input must not panic or split a rune.
	multi := "naïve/café/résumé/path/with/üñïçödé/characters.env"
	mgot := truncate(multi, 10)
	if len([]rune(mgot)) != 10 {
		t.Errorf("multibyte truncate length = %d runes, want 10: %q", len([]rune(mgot)), mgot)
	}
}

// TestIsTTYBuffer asserts IsTTY returns false for a non-*os.File writer (the
// common pipeline case), which is what drives the NDJSON fallback.
func TestIsTTYBuffer(t *testing.T) {
	if IsTTY(&bytes.Buffer{}) {
		t.Error("a bytes.Buffer must not be reported as a TTY")
	}
	// A regular file is a *os.File but not a character device, so also not a TTY.
	f, err := os.CreateTemp(t.TempDir(), "tui-tty-*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer f.Close()
	if IsTTY(f) {
		t.Error("a regular file must not be reported as a TTY")
	}
}

// TestEmitConcurrentSafe runs many concurrent Emits to flush out data races on
// the shared counters and ring under -race. The data path scans on one goroutine
// today, but the sink makes no such guarantee, so it must lock.
func TestEmitConcurrentSafe(t *testing.T) {
	var buf bytes.Buffer
	s := New(Config{Writer: &buf, TTY: false, MaxRecent: 5})

	var wg sync.WaitGroup
	const n = 50
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Emit(context.Background(), finding("rule", 0.8))
		}()
	}
	wg.Wait()

	s.mu.Lock()
	total := s.total
	s.mu.Unlock()
	if total != n {
		t.Errorf("total = %d after %d concurrent emits, want %d", total, n, n)
	}
}

// TestImplementsSinkInterface is a compile-time-ish assertion that *Sink
// satisfies output.Sink, so the pipeline can use it interchangeably with NDJSON.
func TestImplementsSinkInterface(t *testing.T) {
	var _ output.Sink = New(Config{Writer: &bytes.Buffer{}})
}
