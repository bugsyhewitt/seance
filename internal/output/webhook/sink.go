// Package webhook implements an output.Sink that POSTs each Finding as JSON to
// a configured HTTP endpoint, turning séance from a pipe you have to babysit
// into a monitor that can page a human channel in real time.
//
// Design constraints, in priority order:
//
//   - Never block the scan pipeline. Emit hands the Finding to a bounded
//     in-memory queue and returns immediately. A single background worker
//     drains the queue and performs the (potentially slow) HTTP POST. If the
//     queue is full — a slow or down endpoint — the Finding is dropped and a
//     counter is incremented rather than stalling the scanner.
//   - Never emit raw secrets. The POST body is the already-redacted Finding;
//     output.Finding has no raw field, so the never-store-raw invariant holds
//     for free.
//   - Fail open. A non-2xx response or transport error is logged to stderr and
//     the run continues. A dead alerting channel must never take down the
//     monitor.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

// defaultQueueSize bounds the number of pending alerts held in memory. Beyond
// this, new findings are dropped (and counted) so a slow endpoint cannot grow
// memory without limit or apply backpressure to the scanner.
const defaultQueueSize = 256

// defaultTimeout caps a single POST so a hung endpoint cannot tie up the worker
// indefinitely.
const defaultTimeout = 10 * time.Second

// Config configures a webhook Sink.
type Config struct {
	// URL is the endpoint each Finding is POSTed to. Required.
	URL string
	// Headers are added to every request (e.g. {"Authorization": "Bearer x"}).
	Headers map[string]string
	// MinConfidence gates alerting: only Findings with Confidence >= this value
	// are POSTed. 0 means alert on everything.
	MinConfidence float64
	// QueueSize overrides the bounded queue depth. 0 uses defaultQueueSize.
	QueueSize int
	// Timeout overrides the per-request timeout. 0 uses defaultTimeout.
	Timeout time.Duration
	// Client overrides the HTTP client (tests inject one). nil uses a client
	// built from Timeout.
	Client *http.Client
	// ErrLog receives non-fatal error lines. nil discards them.
	ErrLog io.Writer
}

// Sink POSTs Findings to an HTTP endpoint via a single background worker fed by
// a bounded queue.
type Sink struct {
	url     string
	headers map[string]string
	minConf float64
	client  *http.Client
	errLog  io.Writer

	queue  chan output.Finding
	wg     sync.WaitGroup
	closed atomic.Bool

	// dropped counts findings discarded because the queue was full.
	dropped atomic.Uint64
	// sent counts findings successfully delivered (2xx response).
	sent atomic.Uint64
	// failed counts findings whose POST returned non-2xx or errored.
	failed atomic.Uint64
}

// New constructs a webhook Sink and starts its background worker.
func New(cfg Config) *Sink {
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = defaultQueueSize
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	// Copy the header map so later mutation by the caller cannot race the worker.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	s := &Sink{
		url:     cfg.URL,
		headers: headers,
		minConf: cfg.MinConfidence,
		client:  client,
		errLog:  cfg.ErrLog,
		queue:   make(chan output.Finding, qsize),
	}

	s.wg.Add(1)
	go s.worker()
	return s
}

// Emit implements output.Sink. It applies the min-confidence gate, then enqueues
// the Finding for the background worker. It never blocks: if the queue is full or
// the sink is closed, the Finding is dropped and counted. Emit always returns nil
// so a slow or dead alerting channel can never fail the scan.
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
		s.logf("séance webhook: queue full, dropped alert for rule=%s repo=%s/%s (alerts_dropped_total=%d)",
			finding.RuleID, finding.RepoOwner, finding.RepoName, s.dropped.Load())
	}
	return nil
}

// worker drains the queue and POSTs each Finding. It exits when the queue is
// closed (by Close) and fully drained.
func (s *Sink) worker() {
	defer s.wg.Done()
	for finding := range s.queue {
		s.post(finding)
	}
}

// post performs a single POST. All errors are non-fatal: logged and counted.
func (s *Sink) post(finding output.Finding) {
	body, err := json.Marshal(finding)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance webhook: marshal error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		s.failed.Add(1)
		s.logf("séance webhook: request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance webhook: POST %s failed: %v", s.url, err)
		return
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused by keep-alive.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.failed.Add(1)
		s.logf("séance webhook: POST %s returned %d for rule=%s repo=%s/%s",
			s.url, resp.StatusCode, finding.RuleID, finding.RepoOwner, finding.RepoName)
		return
	}
	s.sent.Add(1)
}

// Close stops accepting new findings, drains the queue, and waits for the worker
// to finish delivering everything already enqueued. Idempotent.
func (s *Sink) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.queue)
	s.wg.Wait()
	return nil
}

// Stats returns delivery counters: findings successfully sent, findings whose
// POST failed (non-2xx or transport error), and findings dropped because the
// queue was full. Useful for the metrics line and tests.
func (s *Sink) Stats() (sent, failed, dropped uint64) {
	return s.sent.Load(), s.failed.Load(), s.dropped.Load()
}

func (s *Sink) logf(format string, args ...any) {
	if s.errLog == nil {
		return
	}
	fmt.Fprintln(s.errLog, fmt.Sprintf(format, args...))
}
