// Package csv implements an output.Sink that exports séance findings as a CSV
// document on shutdown — the lingua franca of spreadsheets, BI tools, ticketing
// imports (Jira / ServiceNow), and ad-hoc grep/awk analysis.
//
// CSV is, like SARIF, a *document* sink rather than a stream: a single header
// row plus one row per finding. The sink therefore BUFFERS each Finding on Emit
// and serializes the complete document once on Close. This fits the
// output.Sink contract exactly — Emit accumulates, Close finalizes — and
// mirrors the sarif sink's lifecycle so an operator can compose --csv-file
// freely alongside --sarif-file, --output-file, --tui, and the webhook.
//
// Design constraints, in priority order:
//
//   - Same redacted body. Every column is sourced from the already-redacted
//     output.Finding, which has no raw-secret field, so the never-store-raw
//     invariant holds for free: a CSV export can never contain a usable
//     secret. The Redacted and Fingerprint columns are the privacy-preserving
//     identifiers downstream tools key off (a triager pastes the fingerprint
//     into --suppress-file; the redacted/masked value confirms which key to
//     rotate without revealing usable material).
//   - Never block the pipeline. Emit only appends to an in-memory slice under
//     a mutex; the (potentially larger) write happens once, at Close.
//   - Fail safely. Close creates the parent directory and writes atomically
//     via a temp file + rename, so a crash mid-write never leaves a partial
//     CSV that a spreadsheet importer would silently truncate. Idempotent
//     Close: a second call is a no-op.
//   - RFC 4180 compliant. The encoding/csv writer handles quoting, embedded
//     commas/quotes/newlines, and CRLF line endings; the rule description and
//     file path can legitimately contain any of those characters.
//
// The column set is deliberately stable and self-describing — header names
// match Finding's JSON tags so an operator who already knows the NDJSON shape
// recognises the CSV columns immediately. Tags are joined with ';' (CSV cells
// cannot themselves be lists) and the timestamp is rendered as RFC 3339 UTC
// for tool-agnostic parsing.
package csv

import (
	"context"
	encodingcsv "encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

// header is the CSV column order — stable, self-describing, and aligned with
// the NDJSON field names so the two outputs are trivially correlated. Changing
// this order is a breaking change for downstream importers.
var header = []string{
	"timestamp",
	"rule_id",
	"rule_description",
	"provider",
	"repo_owner",
	"repo_name",
	"commit_sha",
	"file_path",
	"line_number",
	"redacted",
	"confidence",
	"tags",
	"fingerprint",
}

// Sink accumulates Findings and, on Close, writes a single CSV document.
type Sink struct {
	path string

	mu       sync.Mutex
	findings []output.Finding
	closed   bool
}

// New returns a CSV sink that will write its document to path on Close.
func New(path string) *Sink {
	return &Sink{path: path}
}

// Emit implements output.Sink. It buffers the (already-redacted) Finding for
// inclusion in the CSV document written at Close. It never blocks on I/O.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.findings = append(s.findings, finding)
	return nil
}

// Close serializes the buffered findings into a CSV document and writes it to
// the configured path. It is idempotent: a second call is a no-op. The parent
// directory is created if missing and the write is atomic (temp file +
// rename) so a partially written report is never observable.
//
// A clean (zero-finding) run still writes a valid header-only document so a
// downstream pipeline can rely on the file existing with the expected schema.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create csv dir %q: %w", dir, err)
		}
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write csv %q: %w", tmp, err)
	}

	w := encodingcsv.NewWriter(f)
	if err := w.Write(header); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, fnd := range s.findings {
		if err := w.Write(rowFor(fnd)); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write csv row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("flush csv: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close csv %q: %w", tmp, err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalize csv %q: %w", s.path, err)
	}
	return nil
}

// rowFor maps one redacted Finding to a CSV row in the documented column
// order. Only redacted / locator fields are referenced — Finding carries no
// raw-secret field, so the never-store-raw invariant holds for the CSV export
// for free.
//
// Tags are joined with ';' because a CSV cell cannot itself be a list; ';' is
// chosen over ',' to avoid forcing an extra layer of quoting on every tagged
// row. The timestamp is rendered as RFC 3339 in UTC so it is portable across
// every spreadsheet/SIEM importer; the zero value renders as an empty cell
// rather than the Go epoch.
//
// Confidence is rendered with two decimals to match the precision an operator
// sees in the NDJSON/SARIF outputs and to avoid spreadsheet importers
// rendering it in scientific notation.
func rowFor(f output.Finding) []string {
	ts := ""
	if !f.Timestamp.IsZero() {
		ts = f.Timestamp.UTC().Format(time.RFC3339)
	}
	return []string{
		ts,
		f.RuleID,
		f.RuleDesc,
		f.Provider,
		f.RepoOwner,
		f.RepoName,
		f.CommitSHA,
		f.FilePath,
		strconv.Itoa(f.LineNumber),
		f.Redacted,
		strconv.FormatFloat(f.Confidence, 'f', 2, 64),
		strings.Join(f.Tags, ";"),
		f.Fingerprint,
	}
}

// Header returns a copy of the CSV column order. Exposed for tests/consumers
// that want to verify the schema without re-deriving it.
func Header() []string {
	out := make([]string, len(header))
	copy(out, header)
	return out
}
