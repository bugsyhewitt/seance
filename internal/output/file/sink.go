// Package file implements an output.Sink that appends each Finding as a line of
// NDJSON to a file on disk, giving séance a durable record of findings that runs
// independently of — and alongside — whatever is on stdout.
//
// The motivating case is --tui: the live terminal feed takes over stdout, so the
// machine-readable NDJSON stream that downstream tooling (jq, a SIEM loader) needs
// has nowhere to go. --output-file lets an operator watch the colored feed AND
// capture every finding to a file at the same time. It is equally useful without
// --tui as a tee: findings stream to stdout for a live pipe and are persisted to a
// file for the record.
//
// Design constraints, in priority order:
//
//   - Same redacted body. Each line is exactly the NDJSON Finding object the
//     stdout sink emits. output.Finding has no raw field, so the never-store-raw
//     invariant holds for free — the file can never contain a usable secret.
//   - Durable but cheap. Writes are buffered and flushed on Close. The parent
//     directory is created if missing so --output-file logs/seance.ndjson works
//     out of the box.
//   - Append, never truncate. The file is opened O_APPEND so restarting séance
//     extends the record instead of erasing prior findings.
package file

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/bugsyhewitt/seance/internal/output"
)

// Sink appends Findings as newline-delimited JSON to a file.
type Sink struct {
	mu  sync.Mutex
	f   *os.File
	bw  *bufio.Writer
	enc *json.Encoder
}

// New opens (creating the parent directory and the file if needed) the file at
// path for appended NDJSON output and returns a Sink writing to it. The file is
// opened O_APPEND|O_CREATE|O_WRONLY so a restart extends the record rather than
// truncating it.
func New(path string) (*Sink, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create output dir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open output file %q: %w", path, err)
	}
	bw := bufio.NewWriter(f)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	return &Sink{f: f, bw: bw, enc: enc}, nil
}

// Emit implements output.Sink. Each call appends one JSON line. Access is
// serialized so the sink is safe to share across the scan engine's callers.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enc == nil {
		return nil
	}
	return s.enc.Encode(finding)
}

// Close flushes the buffer and closes the underlying file. Idempotent: a second
// call is a no-op. After Close, Emit silently drops findings.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	flushErr := s.bw.Flush()
	closeErr := s.f.Close()
	s.enc = nil
	s.bw = nil
	s.f = nil
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
