// Package splunkhec implements an output.Sink that ships each Finding to a
// Splunk HTTP Event Collector endpoint as a JSON-wrapped HEC event, turning
// séance into a feed the rest of a Splunk-centric SOC can dashboard, alert
// on, and correlate alongside its other security telemetry.
//
// Design constraints, in priority order, mirror the webhook and syslog sinks:
//
//   - Never block the scan pipeline. Emit hands the Finding to a bounded
//     in-memory queue and returns immediately. A single background worker
//     drains the queue and performs the (potentially slow) HEC POST. If the
//     queue is full — a slow or down HEC endpoint — the Finding is dropped and
//     a counter is incremented rather than stalling the scanner.
//   - Never emit raw secrets. The HEC event body is the already-redacted
//     Finding wrapped in HEC's envelope; output.Finding has no raw field, so
//     the never-store-raw invariant holds for free.
//   - Fail open. A non-2xx response or transport error is logged to stderr and
//     the run continues. A dead SIEM channel must never take down the monitor.
package splunkhec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

const (
	defaultQueueSize  = 256
	defaultTimeout    = 10 * time.Second
	defaultSource     = "seance"
	defaultSourceType = "seance:finding"
)

// Config configures a Splunk HEC Sink.
type Config struct {
	// URL is the full HEC endpoint each Finding is POSTed to. Typically
	// "https://splunk.example.com:8088/services/collector/event". Required.
	URL string
	// Token is the HEC token. Required. Sent as "Authorization: Splunk <token>".
	Token string
	// Index optionally pins every event to a specific Splunk index. Empty uses
	// the HEC token's default index.
	Index string
	// Source overrides the HEC `source` field. Empty uses "seance".
	Source string
	// SourceType overrides the HEC `sourcetype` field. Empty uses
	// "seance:finding" — pick a name Splunk admins can target with a props.conf
	// entry for field extraction.
	SourceType string
	// Host overrides the HEC `host` field. Empty omits it, letting Splunk pick.
	Host string
	// MinConfidence gates shipping: only Findings with Confidence >= this value
	// are POSTed. 0 ships everything.
	MinConfidence float64
	// InsecureSkipVerify disables TLS certificate verification on the HEC
	// connection. Enterprise HEC deployments routinely sit behind a self-signed
	// or internal-CA certificate; this lets séance ship to them without the
	// operator having to bundle a CA. Default false — verify like any HTTPS
	// client.
	InsecureSkipVerify bool
	// QueueSize overrides the bounded queue depth. 0 uses defaultQueueSize.
	QueueSize int
	// Timeout overrides the per-request timeout. 0 uses defaultTimeout.
	Timeout time.Duration
	// Client overrides the HTTP client (tests inject one). nil uses a client
	// built from Timeout and InsecureSkipVerify.
	Client *http.Client
	// ErrLog receives non-fatal error lines. nil discards them.
	ErrLog io.Writer
}

// Sink POSTs Findings to a Splunk HEC endpoint via a single background worker
// fed by a bounded queue.
type Sink struct {
	url        string
	token      string
	index      string
	source     string
	sourceType string
	host       string
	minConf    float64
	client     *http.Client
	errLog     io.Writer

	queue  chan output.Finding
	wg     sync.WaitGroup
	closed atomic.Bool

	dropped atomic.Uint64
	sent    atomic.Uint64
	failed  atomic.Uint64
}

// hecEvent is the JSON envelope HEC expects on /services/collector/event.
// Splunk's documented field order is irrelevant — these are JSON keys, not
// positional — but the field names and casing are wire-mandatory.
type hecEvent struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host,omitempty"`
	Source     string         `json:"source,omitempty"`
	SourceType string         `json:"sourcetype,omitempty"`
	Index      string         `json:"index,omitempty"`
	Event      output.Finding `json:"event"`
}

// New constructs a Splunk HEC Sink and starts its background worker.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("splunk-hec: URL is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("splunk-hec: token is required")
	}
	if cfg.MinConfidence < 0 || cfg.MinConfidence > 1 {
		return nil, fmt.Errorf("splunk-hec: min-confidence must be between 0.0 and 1.0, got %.2f", cfg.MinConfidence)
	}

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
		// A fresh Transport (not DefaultTransport) so toggling InsecureSkipVerify
		// for séance never mutates a shared global used by other code.
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		}
		client = &http.Client{Timeout: timeout, Transport: tr}
	}

	source := cfg.Source
	if source == "" {
		source = defaultSource
	}
	sourceType := cfg.SourceType
	if sourceType == "" {
		sourceType = defaultSourceType
	}

	s := &Sink{
		url:        cfg.URL,
		token:      cfg.Token,
		index:      cfg.Index,
		source:     source,
		sourceType: sourceType,
		host:       cfg.Host,
		minConf:    cfg.MinConfidence,
		client:     client,
		errLog:     cfg.ErrLog,
		queue:      make(chan output.Finding, qsize),
	}

	s.wg.Add(1)
	go s.worker()
	return s, nil
}

// Emit implements output.Sink. Non-blocking, fail-open.
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
		s.dropped.Add(1)
		s.logf("séance splunk-hec: queue full, dropped event for rule=%s repo=%s/%s (events_dropped_total=%d)",
			finding.RuleID, finding.RepoOwner, finding.RepoName, s.dropped.Load())
	}
	return nil
}

func (s *Sink) worker() {
	defer s.wg.Done()
	for finding := range s.queue {
		s.post(finding)
	}
}

func (s *Sink) post(finding output.Finding) {
	ts := finding.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	envelope := hecEvent{
		// HEC accepts time as epoch seconds with sub-second precision as a float.
		Time:       float64(ts.UnixNano()) / 1e9,
		Host:       s.host,
		Source:     s.source,
		SourceType: s.sourceType,
		Index:      s.index,
		Event:      finding,
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance splunk-hec: marshal error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		s.failed.Add(1)
		s.logf("séance splunk-hec: request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance splunk-hec: POST %s failed: %v", s.url, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.failed.Add(1)
		s.logf("séance splunk-hec: POST %s returned %d for rule=%s repo=%s/%s",
			s.url, resp.StatusCode, finding.RuleID, finding.RepoOwner, finding.RepoName)
		return
	}
	s.sent.Add(1)
}

// Close stops accepting new findings, drains the queue, and waits for the
// worker to finish. Idempotent.
func (s *Sink) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.queue)
	s.wg.Wait()
	return nil
}

// Stats returns delivery counters: events successfully sent, events whose POST
// failed (non-2xx or transport error), and events dropped because the queue was
// full. Useful for the metrics line and tests.
func (s *Sink) Stats() (sent, failed, dropped uint64) {
	return s.sent.Load(), s.failed.Load(), s.dropped.Load()
}

func (s *Sink) logf(format string, args ...any) {
	if s.errLog == nil {
		return
	}
	fmt.Fprintln(s.errLog, fmt.Sprintf(format, args...))
}
