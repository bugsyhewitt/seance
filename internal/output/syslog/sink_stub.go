// Platform stub for systems where the stdlib log/syslog package does not build
// (Windows, Plan 9). Keeping the package compileable everywhere lets the rest
// of séance (and its tests) build on those platforms while still failing loudly
// — rather than silently dropping findings — if an operator configures
// --syslog-addr on an unsupported host.
//
//go:build windows || plan9

package syslog

import (
	"context"
	"errors"
	"io"

	"github.com/bugsyhewitt/seance/internal/output"
)

// ErrUnsupported is returned by New on platforms where the stdlib syslog
// package is not available. The caller (the pipeline wiring) translates this
// into a fatal startup error so an operator who asks for syslog output on a
// system that cannot provide it learns immediately instead of after a silent
// run with no findings shipped.
var ErrUnsupported = errors.New("syslog sink is not supported on this platform")

// Priority is a stand-in for syslog.Priority so the package's public Config
// type compiles on every platform. On unsupported platforms it is opaque and
// has no effect — the sink cannot be constructed at all.
type Priority int

// Writer is the empty interface form of the real Writer for compile-only parity.
type Writer interface{ Close() error }

// Config mirrors the Unix-build Config so the rest of séance compiles
// platform-agnostically.
type Config struct {
	Network       string
	Addr          string
	Tag           string
	Facility      Priority
	FixedSeverity Priority
	MinConfidence float64
	QueueSize     int
	Dialer        func(network, raddr string, priority Priority, tag string) (Writer, error)
	ErrLog        io.Writer
}

// Sink is a non-functional placeholder on unsupported platforms.
type Sink struct{}

// New always returns nil and ErrUnsupported on this platform.
func New(_ Config) (*Sink, error) { return nil, ErrUnsupported }

// Emit is a no-op (the sink is never constructed on this platform).
func (s *Sink) Emit(_ context.Context, _ output.Finding) error { return nil }

// Close is a no-op (the sink is never constructed on this platform).
func (s *Sink) Close() error { return nil }

// Stats is a no-op (the sink is never constructed on this platform).
func (s *Sink) Stats() (sent, failed, dropped uint64) { return 0, 0, 0 }
