// Package syslog implements an output.Sink that ships each Finding as a redacted
// JSON message to a syslog endpoint — the local /dev/log socket by default, or a
// remote UDP/TCP collector — turning séance into a SIEM-friendly monitor that an
// operator can wire into their existing log aggregation pipeline (rsyslog,
// syslog-ng, journald, Splunk, ELK, Datadog) without any relay.
//
// Design constraints, in priority order:
//
//   - Never block the scan pipeline. Emit hands the Finding to a bounded
//     in-memory queue and returns immediately. A single background worker
//     drains the queue and performs the (potentially slow) syslog write. If the
//     queue is full — a slow or down collector — the Finding is dropped and a
//     counter is incremented rather than stalling the scanner.
//   - Never emit raw secrets. The message body is the already-redacted Finding
//     marshalled as JSON; output.Finding has no raw field, so the
//     never-store-raw invariant holds for free.
//   - Fail open. A write error is logged to stderr and the run continues; on a
//     transient error the worker transparently reconnects on the next message
//     so a momentarily-restarting collector does not silently swallow findings
//     for the rest of the run. A dead syslog channel must never take down the
//     monitor.
//   - Severity from confidence. Each Finding's confidence score maps to a
//     syslog severity (high → WARNING/ALERT, low → INFO/DEBUG) so SIEM rules
//     can fire on severity directly without re-parsing the JSON body. The
//     mapping is overridable for operators who want everything at a fixed
//     level.
//
// This sink is unix-only — the stdlib's log/syslog package does not build on
// Windows or Plan 9. A platform-stub sibling file returns a clear error on those
// platforms so the rest of séance still compiles.
//
//go:build !windows && !plan9

package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bugsyhewitt/seance/internal/output"
)

// defaultQueueSize bounds the number of pending syslog messages held in memory.
// Beyond this, new findings are dropped (and counted) so a slow collector cannot
// grow memory without limit or apply backpressure to the scanner.
const defaultQueueSize = 256

// defaultTag is the syslog tag (program name) séance uses when the operator
// does not override it. It is short, lowercase, and contains no spaces so it
// parses cleanly in every syslog implementation.
const defaultTag = "seance"

// defaultFacility is the syslog facility séance writes to when the operator
// does not override it. LOG_USER is the right default for an end-user
// application; security teams that want séance findings on a dedicated channel
// can route to LOG_LOCAL0..7 via --syslog-facility.
const defaultFacility = syslog.LOG_USER

// Config configures a syslog Sink.
type Config struct {
	// Network is the transport for the syslog connection: "" (local syslog via
	// the system's well-known socket — /dev/log on Linux, /var/run/syslog on
	// macOS), "udp", "tcp", "unixgram", or "unix". When Network is empty Addr
	// must also be empty.
	Network string
	// Addr is the network address of a remote syslog server (e.g.
	// "collector.example.com:514") or the path to a unix-domain socket. Empty
	// means "use the local syslog socket".
	Addr string
	// Tag is the syslog tag (the "program name" field in the RFC3164 message
	// header). Empty uses "seance".
	Tag string
	// Facility is the syslog facility for every message. Zero uses LOG_USER.
	// Use syslog.LOG_LOCAL0..LOG_LOCAL7 to route findings to a dedicated
	// channel separate from other user-facility traffic.
	Facility syslog.Priority
	// FixedSeverity, when non-zero, pins every message to this severity instead
	// of mapping from finding confidence. Useful when an operator wants
	// uniform-severity output (e.g. all WARNING) for a downstream rule that
	// keys off severity.
	FixedSeverity syslog.Priority
	// MinConfidence gates emission: only Findings with Confidence >= this value
	// are sent. 0 means emit everything.
	MinConfidence float64
	// QueueSize overrides the bounded queue depth. 0 uses defaultQueueSize.
	QueueSize int
	// Dialer overrides the syslog writer constructor (tests inject one). When
	// nil the sink calls syslog.Dial(Network, Addr, Facility|INFO, Tag) — INFO
	// here is a placeholder priority; per-message priority is computed at write
	// time and is what actually appears in the RFC3164 header.
	Dialer func(network, raddr string, priority syslog.Priority, tag string) (Writer, error)
	// ErrLog receives non-fatal error lines. nil discards them.
	ErrLog io.Writer
}

// Writer is the narrow interface the Sink needs from a syslog connection. The
// real log/syslog.Writer satisfies it; tests substitute an in-memory implementation.
// We re-declare the subset of methods we use (one per severity level we map to)
// so the sink is decoupled from the concrete *syslog.Writer at the type level
// and a test fake doesn't need to embed an open socket.
type Writer interface {
	Emerg(m string) error
	Alert(m string) error
	Crit(m string) error
	Err(m string) error
	Warning(m string) error
	Notice(m string) error
	Info(m string) error
	Debug(m string) error
	Close() error
}

// realDial wraps syslog.Dial to satisfy the Dialer signature.
func realDial(network, raddr string, priority syslog.Priority, tag string) (Writer, error) {
	w, err := syslog.Dial(network, raddr, priority, tag)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// Sink ships Findings to a syslog endpoint via a single background worker fed
// by a bounded queue.
type Sink struct {
	network       string
	addr          string
	tag           string
	facility      syslog.Priority
	fixedSeverity syslog.Priority
	minConf       float64
	dialer        func(network, raddr string, priority syslog.Priority, tag string) (Writer, error)
	errLog        io.Writer

	// w is the active syslog writer. It is created lazily on the first write
	// and recreated after a transient failure so a momentarily-restarting
	// collector does not silently swallow the rest of the run.
	w Writer

	queue  chan output.Finding
	wg     sync.WaitGroup
	closed atomic.Bool

	// dropped counts findings discarded because the queue was full.
	dropped atomic.Uint64
	// sent counts findings successfully written to the syslog writer.
	sent atomic.Uint64
	// failed counts findings whose write returned an error.
	failed atomic.Uint64
}

// New constructs a syslog Sink and starts its background worker. The syslog
// connection itself is established lazily on the first emitted finding so a
// down collector at startup does not delay or fail the scan; it is also
// reconnected transparently after a transient write error.
//
// New returns (*Sink, error) for parity with the platform-stub New on
// unsupported systems (Windows, Plan 9) — on Unix the error is always nil
// because connection establishment is deferred to the worker.
func New(cfg Config) (*Sink, error) {
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = defaultQueueSize
	}
	tag := cfg.Tag
	if tag == "" {
		tag = defaultTag
	}
	facility := cfg.Facility
	if facility == 0 {
		facility = defaultFacility
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = realDial
	}

	s := &Sink{
		network:       cfg.Network,
		addr:          cfg.Addr,
		tag:           tag,
		facility:      facility,
		fixedSeverity: cfg.FixedSeverity,
		minConf:       cfg.MinConfidence,
		dialer:        dialer,
		errLog:        cfg.ErrLog,
		queue:         make(chan output.Finding, qsize),
	}

	s.wg.Add(1)
	go s.worker()
	return s, nil
}

// Emit implements output.Sink. It applies the min-confidence gate, then
// enqueues the Finding for the background worker. It never blocks: if the
// queue is full or the sink is closed, the Finding is dropped and counted.
// Emit always returns nil so a slow or dead syslog channel can never fail
// the scan.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	if finding.Confidence < s.minConf {
		return nil
	}
	if s.closed.Load() {
		s.dropped.Add(1)
		return nil
	}
	select {
	case s.queue <- finding:
	default:
		// Queue full — drop rather than block the pipeline.
		s.dropped.Add(1)
		s.logf("séance syslog: queue full, dropped finding for rule=%s repo=%s/%s (syslog_dropped_total=%d)",
			finding.RuleID, finding.RepoOwner, finding.RepoName, s.dropped.Load())
	}
	return nil
}

// worker drains the queue and writes each Finding. It exits when the queue is
// closed (by Close) and fully drained.
func (s *Sink) worker() {
	defer s.wg.Done()
	for finding := range s.queue {
		s.write(finding)
	}
	if s.w != nil {
		_ = s.w.Close()
		s.w = nil
	}
}

// write performs a single syslog write, dialing lazily on first call and
// reconnecting transparently after a transient error. All errors are
// non-fatal: logged and counted.
func (s *Sink) write(finding output.Finding) {
	body, err := marshal(finding)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance syslog: marshal error: %v", err)
		return
	}

	if s.w == nil {
		// Lazy initial dial. The placeholder priority handed to Dial only sets
		// the writer's default; the per-message severity routing below is what
		// the RFC3164 header reflects.
		w, derr := s.dialer(s.network, s.addr, s.facility|syslog.LOG_INFO, s.tag)
		if derr != nil {
			s.failed.Add(1)
			s.logf("séance syslog: dial %s/%s failed: %v", s.network, s.addr, derr)
			return
		}
		s.w = w
	}

	severity := s.severityFor(finding)
	if werr := writeAt(s.w, severity, body); werr != nil {
		s.failed.Add(1)
		s.logf("séance syslog: write failed: %v (will reconnect on next finding)", werr)
		// Close and clear the writer so the next call re-dials. A
		// momentarily-restarting collector then recovers without
		// silently swallowing the rest of the run.
		_ = s.w.Close()
		s.w = nil
		return
	}
	s.sent.Add(1)
}

// severityFor picks the syslog severity for a finding. If FixedSeverity is set,
// every finding writes at that severity; otherwise severity is derived from the
// confidence score so SIEM rules can fire on header severity alone.
func (s *Sink) severityFor(finding output.Finding) syslog.Priority {
	if s.fixedSeverity != 0 {
		return s.fixedSeverity
	}
	switch {
	case finding.Confidence >= 0.95:
		return syslog.LOG_ALERT
	case finding.Confidence >= 0.85:
		return syslog.LOG_CRIT
	case finding.Confidence >= 0.70:
		return syslog.LOG_ERR
	case finding.Confidence >= 0.50:
		return syslog.LOG_WARNING
	case finding.Confidence >= 0.30:
		return syslog.LOG_NOTICE
	default:
		return syslog.LOG_INFO
	}
}

// writeAt routes a single message to the syslog writer's method for the given
// severity. log/syslog.Writer's API is one method per severity, not a generic
// Write(priority, body), so we dispatch here.
func writeAt(w Writer, severity syslog.Priority, body string) error {
	switch severity & 0x07 { // severity is the low 3 bits
	case syslog.LOG_EMERG:
		return w.Emerg(body)
	case syslog.LOG_ALERT:
		return w.Alert(body)
	case syslog.LOG_CRIT:
		return w.Crit(body)
	case syslog.LOG_ERR:
		return w.Err(body)
	case syslog.LOG_WARNING:
		return w.Warning(body)
	case syslog.LOG_NOTICE:
		return w.Notice(body)
	case syslog.LOG_INFO:
		return w.Info(body)
	case syslog.LOG_DEBUG:
		return w.Debug(body)
	default:
		return w.Info(body)
	}
}

// marshal renders a Finding to a one-line JSON string — the same shape the
// NDJSON sink emits — so downstream SIEM pipelines can decode séance findings
// with one parser regardless of which transport delivered them.
func marshal(finding output.Finding) (string, error) {
	b, err := json.Marshal(finding)
	if err != nil {
		return "", err
	}
	// Defensive: a syslog message body must be single-line. json.Marshal
	// produces no internal newlines for an output.Finding (no string field
	// legitimately contains a raw newline), but a stray one in the future
	// would split the message across two log lines and corrupt the stream.
	s := strings.ReplaceAll(string(b), "\n", " ")
	return s, nil
}

// Close stops accepting new findings, drains the queue, and waits for the
// worker to finish writing everything already enqueued. The underlying syslog
// connection is closed by the worker as it exits. Idempotent.
func (s *Sink) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.queue)
	s.wg.Wait()
	return nil
}

// Stats returns delivery counters: findings successfully written, findings
// whose write failed, and findings dropped because the queue was full. Useful
// for the metrics line and tests.
func (s *Sink) Stats() (sent, failed, dropped uint64) {
	return s.sent.Load(), s.failed.Load(), s.dropped.Load()
}

func (s *Sink) logf(format string, args ...any) {
	if s.errLog == nil {
		return
	}
	fmt.Fprintf(s.errLog, format+"\n", args...)
}
