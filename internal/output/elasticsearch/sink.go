// Package elasticsearch implements an output.Sink that indexes each Finding
// into an Elasticsearch cluster using the Elasticsearch REST Index API
// (POST /<index>/_doc), turning séance into a live feed the rest of an
// ELK/OpenSearch-centric SOC can search, dashboard, and alert on without a
// Logstash relay or Beats agent.
//
// Design constraints, in priority order, mirror the webhook, syslog, and
// splunkhec sinks:
//
//   - Never block the scan pipeline. Emit hands the Finding to a bounded
//     in-memory queue and returns immediately. A single background worker
//     drains the queue and performs the (potentially slow) HTTP POST. If the
//     queue is full — a slow or down cluster — the Finding is dropped and a
//     counter is incremented rather than stalling the scanner.
//   - Never emit raw secrets. The indexed document is the already-redacted
//     Finding wrapped in a minimal metadata envelope; output.Finding has no
//     raw field, so the never-store-raw invariant holds for free.
//   - Fail open. A non-2xx response or transport error is logged to stderr and
//     the run continues. A dead SIEM channel must never take down the monitor.
//
// The document body is the redacted Finding JSON; Elasticsearch infers the
// mapping automatically on the first document, so no index template is
// required. The optional ApiKey / Username+Password fields cover both modern
// (API-key) and legacy (HTTP Basic) authentication. With ElasticsearchURL
// empty the sink is absent entirely and the data path is byte-for-byte
// unchanged.
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/output/httpclient"
)

const (
	defaultQueueSize = 256
	defaultTimeout   = 10 * time.Second
	defaultIndex     = "seance-findings"
)

// Config configures an Elasticsearch Sink.
type Config struct {
	// URL is the base URL of the Elasticsearch cluster, e.g.
	// "https://elastic.example.com:9200". Required.
	URL string
	// Index is the Elasticsearch index to write documents into. Defaults to
	// "seance-findings". A date-suffix pattern (e.g. "seance-%Y.%m.%d") is not
	// interpreted here — set a static name or an ILM alias.
	Index string
	// ApiKey, when non-empty, is sent as "Authorization: ApiKey <ApiKey>".
	// Takes precedence over Username/Password when both are set.
	ApiKey string
	// Username and Password are used for HTTP Basic auth when ApiKey is empty.
	Username string
	Password string
	// MinConfidence gates indexing: only Findings with Confidence >= this value
	// are sent. 0 ships everything.
	MinConfidence float64
	// InsecureSkipVerify disables TLS certificate verification. Self-managed
	// clusters routinely use self-signed or internal-CA certificates; this lets
	// séance index into them without bundling a CA. Default false (verify).
	InsecureSkipVerify bool
	// QueueSize overrides the bounded queue depth. 0 uses defaultQueueSize.
	QueueSize int
	// Timeout overrides the per-request timeout. 0 uses defaultTimeout.
	Timeout time.Duration
	// Client overrides the HTTP client (tests inject one). nil builds one from
	// Timeout and InsecureSkipVerify.
	Client *http.Client
	// ErrLog receives non-fatal error lines. nil discards them.
	ErrLog io.Writer
}

// Sink POSTs Findings to an Elasticsearch cluster via a single background
// worker fed by a bounded queue.
type Sink struct {
	url      string
	index    string
	apiKey   string
	username string
	password string
	minConf  float64
	timeout  time.Duration
	client   *http.Client
	errLog   io.Writer

	queue  chan output.Finding
	wg     sync.WaitGroup
	closed atomic.Bool

	dropped atomic.Uint64
	sent    atomic.Uint64
	failed  atomic.Uint64
}

// New constructs an Elasticsearch Sink and starts its background worker.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("elasticsearch: URL is required")
	}
	if cfg.ApiKey == "" && (cfg.Username != "" && cfg.Password == "") {
		return nil, fmt.Errorf("elasticsearch: password is required when username is set")
	}
	if err := output.ValidateConfidence("elasticsearch", cfg.MinConfidence); err != nil {
		return nil, err
	}

	index := cfg.Index
	if index == "" {
		index = defaultIndex
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
		client = httpclient.New(timeout, cfg.InsecureSkipVerify)
	}

	s := &Sink{
		url:      strings.TrimRight(cfg.URL, "/"),
		index:    index,
		apiKey:   cfg.ApiKey,
		username: cfg.Username,
		password: cfg.Password,
		minConf:  cfg.MinConfidence,
		timeout:  timeout,
		client:   client,
		errLog:   cfg.ErrLog,
		queue:    make(chan output.Finding, qsize),
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
		s.logf("séance elasticsearch: queue full, dropped event for rule=%s repo=%s/%s (events_dropped_total=%d)",
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

// post indexes one Finding via POST /<index>/_doc (auto-ID assignment).
func (s *Sink) post(finding output.Finding) {
	body, err := json.Marshal(finding)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance elasticsearch: marshal error: %v", err)
		return
	}

	endpoint := fmt.Sprintf("%s/%s/_doc", s.url, s.index)

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		s.failed.Add(1)
		s.logf("séance elasticsearch: request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Authentication: API key takes precedence; fall back to HTTP Basic.
	if s.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+s.apiKey)
	} else if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance elasticsearch: POST %s failed: %v", endpoint, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.failed.Add(1)
		s.logf("séance elasticsearch: POST %s returned %d for rule=%s repo=%s/%s",
			endpoint, resp.StatusCode, finding.RuleID, finding.RepoOwner, finding.RepoName)
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

// Stats returns delivery counters: events successfully indexed, events whose
// POST failed (non-2xx or transport error), and events dropped because the
// queue was full. Useful for metrics lines and tests.
func (s *Sink) Stats() (sent, failed, dropped uint64) {
	return s.sent.Load(), s.failed.Load(), s.dropped.Load()
}

func (s *Sink) logf(format string, args ...any) {
	if s.errLog == nil {
		return
	}
	fmt.Fprintf(s.errLog, format+"\n", args...)
}
