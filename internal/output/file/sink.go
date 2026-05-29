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
//   - Bounded growth (opt-in). séance's intended deployment is a run-forever
//     monitor, where an append-only file grows without limit. When a max size is
//     configured the sink rotates: the active file is renamed aside (keeping a
//     small fixed number of older generations) and a fresh file is opened, so the
//     on-disk record stays bounded without an external logrotate. With no max size
//     the behaviour is byte-for-byte the prior append-forever sink.
package file

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/bugsyhewitt/seance/internal/output"
)

// keptGenerations is the number of rotated files séance retains alongside the
// active file when rotation is enabled. With the active findings.ndjson this
// keeps findings.ndjson, findings.ndjson.1, findings.ndjson.2, findings.ndjson.3
// — four files total — and discards anything older on the next rotation. The
// count is fixed (not a flag) to keep the rotation contract simple: the operator
// tunes total disk via --output-max-bytes, and the kept-generation count bounds
// it to roughly (keptGenerations+1) * max-bytes.
const keptGenerations = 3

// Sink appends Findings as newline-delimited JSON to a file, optionally rotating
// the file once it would exceed a configured byte size.
type Sink struct {
	mu  sync.Mutex
	f   *os.File
	bw  *bufio.Writer
	enc *json.Encoder

	// path is the active file path, retained so the sink can rotate it.
	path string
	// maxBytes is the rotation threshold in bytes; 0 disables rotation (the
	// append-forever behaviour). When >0 the active file is rotated before a
	// write that would carry it past this size.
	maxBytes int64
	// size tracks the current on-disk byte length of the active file so the
	// rotation decision needs no stat per write. Seeded from the file's length
	// at New (so an appended-to file rotates based on its true size, not just
	// bytes this process wrote) and reset to 0 after each rotation.
	size int64
}

// New opens (creating the parent directory and the file if needed) the file at
// path for appended NDJSON output and returns a Sink writing to it. The file is
// opened O_APPEND|O_CREATE|O_WRONLY so a restart extends the record rather than
// truncating it. Rotation is disabled; use NewWithRotation to bound file size.
func New(path string) (*Sink, error) {
	return NewWithRotation(path, 0)
}

// NewWithRotation is New with size-based rotation. When maxBytes > 0 the active
// file is rotated (renamed aside, a fresh file opened) before any write that
// would carry it past maxBytes, keeping a small fixed number of older
// generations so the total on-disk record stays bounded. maxBytes <= 0 disables
// rotation and behaves exactly like New (append forever).
func NewWithRotation(path string, maxBytes int64) (*Sink, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create output dir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open output file %q: %w", path, err)
	}
	// Seed the running size from the file's current length so a sink opened on a
	// pre-existing (appended-to) file rotates based on its true size, not just the
	// bytes this process has written.
	var size int64
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	bw := bufio.NewWriter(f)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	return &Sink{f: f, bw: bw, enc: enc, path: path, maxBytes: maxBytes, size: size}, nil
}

// Emit implements output.Sink. Each call appends one JSON line. Access is
// serialized so the sink is safe to share across the scan engine's callers. When
// rotation is enabled and the active file would exceed the configured size, the
// file is rotated before the line is written so a single finding is never split
// across two generations.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enc == nil {
		return nil
	}

	// Marshal first so we know the exact byte length (including the trailing
	// newline json.Encoder appends) before committing to a file. This keeps the
	// rotation decision precise and ensures one finding lands wholly in one file.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(finding); err != nil {
		return err
	}
	line := buf.Bytes()

	// Rotate when a non-empty file would grow past the limit. The first finding
	// always lands in a fresh file even if it alone exceeds the limit (size == 0),
	// so a single oversized line is never lost to an infinite rotation loop.
	if s.maxBytes > 0 && s.size > 0 && s.size+int64(len(line)) > s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}

	if _, err := s.bw.Write(line); err != nil {
		return err
	}
	s.size += int64(len(line))
	return nil
}

// rotate flushes and closes the active file, shifts the retained generations up
// by one (path.(n) -> path.(n+1)), discards the oldest beyond keptGenerations,
// renames the active file to path.1, and opens a fresh active file. The caller
// must hold s.mu. On any error the sink is left usable: if reopening fails the
// old handles are already gone, so Emit becomes a silent no-op (enc == nil)
// rather than writing to a closed file.
func (s *Sink) rotate() error {
	if err := s.bw.Flush(); err != nil {
		return err
	}
	if err := s.f.Close(); err != nil {
		return err
	}

	// Drop the oldest generation, then shift each remaining one up by one slot.
	// Missing files are skipped — a young record may not have every generation yet.
	oldest := fmt.Sprintf("%s.%d", s.path, keptGenerations)
	_ = os.Remove(oldest)
	for i := keptGenerations - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", s.path, i)
		to := fmt.Sprintf("%s.%d", s.path, i+1)
		if _, err := os.Stat(from); err == nil {
			if err := os.Rename(from, to); err != nil {
				return fmt.Errorf("rotate %q -> %q: %w", from, to, err)
			}
		}
	}
	// Move the active file to the .1 slot.
	if err := os.Rename(s.path, s.path+".1"); err != nil {
		return fmt.Errorf("rotate active file %q: %w", s.path, err)
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		// The active file is gone and we could not reopen: disable the sink so
		// Emit degrades to a no-op instead of panicking on nil handles.
		s.enc = nil
		s.bw = nil
		s.f = nil
		return fmt.Errorf("reopen output file %q after rotation: %w", s.path, err)
	}
	s.f = f
	s.bw = bufio.NewWriter(f)
	s.enc = json.NewEncoder(s.bw)
	s.enc.SetEscapeHTML(false)
	s.size = 0
	return nil
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
