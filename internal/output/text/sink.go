// Package text implements an output.Sink that streams each Finding as a single
// compact, human-readable line — the plain-text counterpart to the NDJSON sink.
//
// It exists to make the long-shipped-but-dead --output / OutputFormat flag real:
// séance always parsed and defaulted OutputFormat to "json" (NDJSON) yet never
// consumed it, so --output had no effect and the help text advertised a single
// value. This sink gives --output a genuine second streaming format for an
// operator tailing the feed live who wants something grep-friendly and readable
// without the NDJSON noise or the full-screen --tui takeover.
//
// Design constraints, in priority order:
//
//   - Same redacted body. Every value written comes from the already-redacted
//     output.Finding, which has no raw-secret field, so the never-store-raw
//     invariant holds for free. The raw secret can never appear in a text line.
//   - Streaming, never blocking. Each Emit writes exactly one line and returns;
//     there is no buffering and no background worker, mirroring the NDJSON sink.
//   - Stable, parseable shape. Fields are space-separated key=value pairs after a
//     leading confidence-bucketed tag, so a line is both eyeball-readable and
//     awk/grep-friendly, and the column order is fixed across releases.
package text

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/bugsyhewitt/seance/internal/output"
)

// Sink writes Findings as one human-readable line each.
type Sink struct {
	w io.Writer
}

// New returns a text sink writing to w.
func New(w io.Writer) *Sink {
	return &Sink{w: w}
}

// Emit implements output.Sink. Each call writes exactly one line describing the
// (already-redacted) finding. The format is:
//
//	[HIGH] rule=aws-access-key repo=alice/repo file=.env:12 conf=0.90 redacted=AKIA****WXYZ fp=abcd1234
//
// Only the redacted value and locator metadata are written; the raw secret is
// never present on the Finding and so can never reach this line.
func (s *Sink) Emit(_ context.Context, f output.Finding) error {
	var b strings.Builder

	b.WriteString(confidenceBucket(f.Confidence))
	b.WriteByte(' ')
	fmt.Fprintf(&b, "rule=%s", nonEmpty(f.RuleID))
	fmt.Fprintf(&b, " repo=%s/%s", nonEmpty(f.RepoOwner), nonEmpty(f.RepoName))
	if f.LineNumber > 0 {
		fmt.Fprintf(&b, " file=%s:%d", nonEmpty(f.FilePath), f.LineNumber)
	} else {
		fmt.Fprintf(&b, " file=%s", nonEmpty(f.FilePath))
	}
	fmt.Fprintf(&b, " conf=%.2f", f.Confidence)
	fmt.Fprintf(&b, " redacted=%s", nonEmpty(f.Redacted))
	if f.Fingerprint != "" {
		fmt.Fprintf(&b, " fp=%s", f.Fingerprint)
	}
	b.WriteByte('\n')

	_, err := io.WriteString(s.w, b.String())
	return err
}

// Close implements output.Sink. No-op for a stream writer.
func (s *Sink) Close() error { return nil }

// confidenceBucket renders a leading severity-style tag so a human scanning the
// stream can triage at a glance and a grep can filter by bucket. The thresholds
// mirror the security-severity bucketing the SARIF sink already uses.
func confidenceBucket(conf float64) string {
	switch {
	case conf >= 0.90:
		return "[HIGH]"
	case conf >= 0.70:
		return "[MED] "
	default:
		return "[LOW] "
	}
}

// nonEmpty substitutes a placeholder for an empty field so a missing value is
// visible rather than producing a dangling "key=" that breaks column parsing.
func nonEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
