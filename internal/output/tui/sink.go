// Package tui implements a live terminal feed sink for séance findings.
//
// Where the NDJSON sink emits one machine-readable JSON object per finding —
// ideal for piping into jq or a log store — the TUI sink renders a human-facing
// live wall: a scrolling list of the most recent findings, colored by
// confidence, with running counters. It is the "watch it work" view, enabled
// with --tui.
//
// Design constraints, in priority order:
//
//   - No risk to the data path. The TUI is just another output.Sink. It never
//     touches raw secret material — it renders the already-redacted Finding, so
//     the never-store-raw invariant holds for free.
//   - Degrade gracefully off a TTY. When stdout is not a terminal (a pipe, a
//     file, CI), a live ANSI feed is meaningless and would corrupt downstream
//     consumers. The caller is expected to fall back to NDJSON in that case;
//     IsTTY is provided so the wiring can make that decision. The sink itself
//     still renders safely (plain lines, no cursor control) if pointed at a
//     non-TTY writer, so tests and odd setups never panic.
//   - Dependency-light. A small hand-rolled ANSI renderer over the stdlib, not a
//     full TUI framework — honoring the anti-abstraction gate.
package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bugsyhewitt/seance/internal/output"
)

// defaultMaxRecent bounds how many recent findings the feed keeps in its
// scrollback ring. Old findings age out of view; counters keep the full totals.
const defaultMaxRecent = 12

// ANSI color codes. Kept tiny and inline rather than pulling a color library.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiGray   = "\x1b[90m"

	// clearScreen + cursorHome together repaint the whole frame each emit. This
	// is the simplest correct full-redraw strategy for a low-frequency feed (the
	// public-events firehose surfaces findings far slower than a render budget).
	clearScreen = "\x1b[2J"
	cursorHome  = "\x1b[H"
)

// Config configures a TUI Sink.
type Config struct {
	// Writer is where frames are rendered. Defaults to os.Stdout.
	Writer io.Writer
	// MaxRecent overrides the scrollback ring depth. 0 uses defaultMaxRecent.
	MaxRecent int
	// TTY tells the sink whether Writer is an interactive terminal. When true,
	// the sink uses cursor control to repaint a live frame in place; when false,
	// it appends plain (uncolored, no cursor control) lines so the output is not
	// corrupted by escape sequences. The wiring layer typically only constructs a
	// TUI sink at all when TTY is true (falling back to NDJSON otherwise), but the
	// sink stays safe either way.
	TTY bool
}

// Sink renders a live, colored feed of findings to a terminal.
type Sink struct {
	w         io.Writer
	maxRecent int
	tty       bool

	mu      sync.Mutex
	recent  []output.Finding // ring of the most recent findings (newest last)
	total   uint64           // cumulative findings seen
	byRule  map[string]uint64
	highest float64 // highest confidence seen this session
}

// New constructs a TUI sink. A nil-Writer config renders to os.Stdout.
func New(cfg Config) *Sink {
	w := cfg.Writer
	if w == nil {
		w = os.Stdout
	}
	maxRecent := cfg.MaxRecent
	if maxRecent <= 0 {
		maxRecent = defaultMaxRecent
	}
	s := &Sink{
		w:         w,
		maxRecent: maxRecent,
		tty:       cfg.TTY,
		byRule:    make(map[string]uint64),
	}
	if s.tty {
		// Paint the empty frame so the operator sees the feed is live before the
		// first finding arrives.
		s.render()
	}
	return s
}

// IsTTY reports whether the given writer is an interactive terminal. The wiring
// layer uses it to decide between the TUI sink (TTY) and the NDJSON sink (pipe,
// file, CI) so a live feed never corrupts a redirected stream.
func IsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Emit implements output.Sink. It records the finding into the rolling counters
// and scrollback, then repaints the frame (TTY) or appends a plain line
// (non-TTY). Emit never errors and never blocks on anything slower than a single
// terminal write.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.total++
	s.byRule[finding.RuleID]++
	if finding.Confidence > s.highest {
		s.highest = finding.Confidence
	}

	s.recent = append(s.recent, finding)
	if len(s.recent) > s.maxRecent {
		// Drop the oldest to bound the ring.
		s.recent = s.recent[len(s.recent)-s.maxRecent:]
	}

	if s.tty {
		s.render()
	} else {
		// Non-TTY: emit a single plain, parseable line per finding. No cursor
		// control, no color, so a redirected stream stays clean.
		fmt.Fprintln(s.w, plainLine(finding))
	}
	return nil
}

// Close implements output.Sink. On a TTY it leaves the final frame on screen and
// drops a trailing newline so the shell prompt returns cleanly. No-op otherwise.
func (s *Sink) Close() error {
	if s.tty {
		fmt.Fprint(s.w, ansiReset+"\n")
	}
	return nil
}

// render repaints the entire frame. Caller must hold s.mu. Only used on a TTY.
func (s *Sink) render() {
	var b []byte
	b = append(b, clearScreen...)
	b = append(b, cursorHome...)

	// Header banner.
	b = appendf(b, "%s%s séance %s— live feed%s\n",
		ansiBold, ansiCyan, ansiReset, ansiReset)
	b = appendf(b, "%s findings=%d  rules_hit=%d  peak_confidence=%s%s\n",
		ansiDim, s.total, len(s.byRule), confidenceStr(s.highest), ansiReset)
	b = appendf(b, "%s%s%s\n", ansiGray, divider(), ansiReset)

	if len(s.recent) == 0 {
		b = appendf(b, "%s  (listening — no findings yet)%s\n", ansiDim, ansiReset)
	}
	// Newest at the bottom so the eye tracks the most recent at a stable spot.
	for _, f := range s.recent {
		b = append(b, renderLine(f)...)
		b = append(b, '\n')
	}
	_, _ = s.w.Write(b)
}

// renderLine formats one finding as a colored terminal row.
func renderLine(f output.Finding) string {
	col := confidenceColor(f.Confidence)
	repo := f.RepoOwner + "/" + f.RepoName
	return fmt.Sprintf("%s%5.0f%%%s  %s%-22s%s  %s%s%s  %s%s%s",
		col, f.Confidence*100, ansiReset,
		ansiBold, truncate(f.RuleID, 22), ansiReset,
		ansiCyan, truncate(repo, 30), ansiReset,
		ansiGray, truncate(f.FilePath, 40), ansiReset,
	)
}

// plainLine formats one finding for a non-TTY writer: no color, no cursor
// control, fixed column order. Stable and grep-friendly.
func plainLine(f output.Finding) string {
	return fmt.Sprintf("[%3.0f%%] %s %s/%s %s",
		f.Confidence*100, f.RuleID, f.RepoOwner, f.RepoName, f.FilePath)
}

// confidenceColor maps a confidence score to an ANSI color: high is red
// (most alarming / most likely real), medium yellow, low green.
func confidenceColor(c float64) string {
	switch {
	case c >= 0.85:
		return ansiRed
	case c >= 0.70:
		return ansiYellow
	default:
		return ansiGreen
	}
}

// confidenceStr renders a colored confidence percentage for the header.
func confidenceStr(c float64) string {
	if c == 0 {
		return ansiGray + "—" + ansiReset + ansiDim
	}
	return fmt.Sprintf("%s%.0f%%%s%s", confidenceColor(c), c*100, ansiReset, ansiDim)
}

func divider() string {
	const w = 60
	d := make([]byte, w)
	for i := range d {
		d[i] = '-'
	}
	return string(d)
}

// truncate shortens s to max runes, appending an ellipsis when cut. It counts
// runes, not bytes, so multibyte paths never split mid-character.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

func appendf(b []byte, format string, args ...any) []byte {
	return append(b, fmt.Sprintf(format, args...)...)
}
