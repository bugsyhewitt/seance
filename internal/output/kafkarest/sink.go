// Package kafkarest implements an output.Sink that ships each Finding to a
// Kafka topic via the Confluent REST Proxy v2 HTTP API (also compatible with
// Redpanda's HTTP Proxy and any other REST Proxy that speaks the same wire
// format), turning séance into a real-time Kafka feed with zero new Go
// dependencies — pure stdlib net/http on top of the same bounded-queue,
// background-worker design used by the Splunk HEC and Elasticsearch sinks.
//
// Wire format: POST /topics/{topic}
//
//	Content-Type: application/vnd.kafka.json.v2+json
//	{
//	  "records": [
//	    {"value": <redacted Finding object>}
//	  ]
//	}
//
// This is the Confluent REST Proxy v2 / Redpanda HTTP Proxy record-produce
// format.  No Kafka client library, no Zookeeper client, no JVM dependency —
// the REST Proxy (or Redpanda HTTP Proxy) translates the HTTP POST into a
// real Kafka produce call on the broker side.
//
// Design constraints, in priority order, mirror every other séance sink:
//
//   - Never block the scan pipeline.  Emit hands the Finding to a bounded
//     in-memory queue and returns immediately.  A single background worker
//     drains the queue and performs the (potentially slow) POST.  If the queue
//     is full — a slow or down REST Proxy — the Finding is dropped and a
//     counter incremented rather than stalling the scanner.
//   - Never emit raw secrets.  The POST body contains only the already-redacted
//     Finding; output.Finding has no raw field, so the never-store-raw invariant
//     holds for free.
//   - Fail open.  A non-2xx response or transport error is logged to stderr and
//     the run continues.  A dead Kafka channel must never take down the monitor.
package kafkarest

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

	// contentType is the Confluent REST Proxy v2 JSON producer content type.
	// Redpanda's HTTP proxy and most REST Proxy implementations accept both
	// this and plain "application/json"; the versioned type is preferred so
	// a strict Confluent deployment doesn't reject the request.
	contentType = "application/vnd.kafka.json.v2+json"
)

// Config configures a Kafka REST Proxy Sink.
type Config struct {
	// URL is the base URL of the Confluent REST Proxy (or Redpanda HTTP Proxy).
	// The topic endpoint is derived as <URL>/topics/<Topic>. Required.
	// Example: "http://kafka-rest.example.com:8082"
	URL string
	// Topic is the Kafka topic each Finding is produced to. Required.
	Topic string
	// Username is used for HTTP Basic auth against the REST Proxy. Optional.
	// Both Username and Password must be set for Basic auth to be sent.
	Username string
	// Password is the password for HTTP Basic auth. Optional.
	// SEANCE_KAFKA_REST_PASSWORD env var is the Docker-friendly fallback.
	Password string
	// APIKey is sent as "Authorization: Bearer <key>" when set. Takes
	// precedence over Username/Password (Confluent Cloud REST API key style).
	// SEANCE_KAFKA_REST_API_KEY env var is the Docker-friendly fallback.
	APIKey string
	// MinConfidence gates shipping: only Findings with Confidence >= this value
	// are produced. 0 ships everything.
	MinConfidence float64
	// InsecureSkipVerify disables TLS certificate verification. Useful for
	// on-prem REST Proxy deployments with self-signed certs. Default false.
	InsecureSkipVerify bool
	// QueueSize overrides the bounded queue depth. 0 uses defaultQueueSize.
	QueueSize int
	// Timeout overrides the per-request timeout. 0 uses defaultTimeout.
	Timeout time.Duration
	// Client overrides the HTTP client (tests inject a fake). nil uses a client
	// built from Timeout and InsecureSkipVerify.
	Client *http.Client
	// ErrLog receives non-fatal error lines. nil discards them.
	ErrLog io.Writer
}

// restRecord is the wire shape for a single record in the REST Proxy v2
// produce request.  The "value" field carries the already-redacted Finding
// directly — no base64 encoding needed because we declare the JSON producer
// content type.
type restRecord struct {
	Value output.Finding `json:"value"`
}

// produceRequest is the full REST Proxy v2 POST body.
type produceRequest struct {
	Records []restRecord `json:"records"`
}

// Sink produces Findings to a Kafka topic via a REST Proxy, using a single
// background worker fed by a bounded queue.
type Sink struct {
	topicURL string // full URL: <base>/topics/<topic>
	username string
	password string
	apiKey   string
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

// New constructs a Kafka REST Proxy Sink and starts its background worker.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("kafka-rest: URL is required")
	}
	if cfg.Topic == "" {
		return nil, fmt.Errorf("kafka-rest: Topic is required")
	}
	if err := output.ValidateConfidence("kafka-rest", cfg.MinConfidence); err != nil {
		return nil, err
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

	// Build the topic URL: strip any trailing slash from the base, then append
	// the standard REST Proxy v2 path segment.
	base := strings.TrimRight(cfg.URL, "/")
	topicURL := base + "/topics/" + cfg.Topic

	s := &Sink{
		topicURL: topicURL,
		username: cfg.Username,
		password: cfg.Password,
		apiKey:   cfg.APIKey,
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
		s.logf("séance kafka-rest: queue full, dropped event for rule=%s repo=%s/%s (events_dropped_total=%d)",
			finding.RuleID, finding.RepoOwner, finding.RepoName, s.dropped.Load())
	}
	return nil
}

func (s *Sink) worker() {
	defer s.wg.Done()
	for finding := range s.queue {
		s.produce(finding)
	}
}

func (s *Sink) produce(finding output.Finding) {
	body, err := json.Marshal(produceRequest{
		Records: []restRecord{{Value: finding}},
	})
	if err != nil {
		s.failed.Add(1)
		s.logf("séance kafka-rest: marshal error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.topicURL, bytes.NewReader(body))
	if err != nil {
		s.failed.Add(1)
		s.logf("séance kafka-rest: request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", contentType)

	// Auth: Bearer token (Confluent Cloud style) takes precedence over Basic.
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	} else if s.username != "" && s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.failed.Add(1)
		s.logf("séance kafka-rest: POST %s failed: %v", s.topicURL, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.failed.Add(1)
		s.logf("séance kafka-rest: POST %s returned %d for rule=%s repo=%s/%s",
			s.topicURL, resp.StatusCode, finding.RuleID, finding.RepoOwner, finding.RepoName)
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
	fmt.Fprintf(s.errLog, format+"\n", args...)
}
