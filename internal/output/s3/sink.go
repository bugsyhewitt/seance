// Package s3 implements an output.Sink that batches redacted Findings into
// NDJSON objects and PUTs them to an S3 (or S3-compatible) bucket, turning
// séance into a feed a security data lake can ingest directly. Athena, Glue,
// EMR, OpenSearch, and every "log → S3 → query" pipeline already know how to
// read NDJSON; this sink lets séance drop straight into that pattern without a
// relay, an agent, or a forwarder.
//
// Why batch instead of one-PUT-per-finding:
//
//   - S3 PUT is priced per request. A monitor that catches thousands of
//     findings a day would generate thousands of objects, exploding cost and
//     making the bucket awful to list/query.
//   - Athena/Glue partition pruning expects a small number of fat files in a
//     YYYY/MM/DD/HH/ layout, not a sea of single-event objects.
//
// So findings are buffered in memory and flushed as one NDJSON object whenever
// either a size threshold or a time interval is reached, plus a final flush on
// Close. This mirrors the canonical pattern used by Firehose, Vector, and
// Fluent Bit's S3 sinks.
//
// Design constraints, in priority order, mirror the other sinks:
//
//   - Never block the scan pipeline. Emit appends to a bounded in-memory
//     buffer and returns immediately. A single background flusher performs
//     the (potentially slow) PUT. If the buffer is full — a slow or down
//     bucket — the Finding is dropped and a counter is incremented rather
//     than stalling the scanner.
//   - Never emit raw secrets. The NDJSON body is the already-redacted
//     Finding; output.Finding has no raw field, so the never-store-raw
//     invariant holds for free.
//   - Fail open. A non-2xx response or transport error is logged to stderr
//     and the run continues; the buffered batch is dropped (not retried
//     indefinitely) so a dead bucket never balloons memory. A dead delivery
//     channel must never take down the monitor.
//   - Zero AWS-SDK dependency. SigV4 is implemented inline with the stdlib.
//     This keeps go.mod the same minimal set the rest of séance enjoys
//     (cobra/pflag/toml), avoids the substantial transitive footprint of
//     aws-sdk-go-v2, and means the binary stays small enough to ship in the
//     existing scratch-based Dockerfile.
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

const (
	defaultRegion        = "us-east-1"
	defaultBatchSize     = 500
	defaultBatchBytes    = 4 * 1024 * 1024 // 4 MiB — well under S3's 5 GiB single-PUT cap, large enough for cheap Athena scans
	defaultFlushInterval = 60 * time.Second
	defaultBufferSize    = 4096
	defaultTimeout       = 30 * time.Second
	defaultService       = "s3"
	emptyPayloadHash     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Config configures an S3 Sink.
type Config struct {
	// Bucket is the destination S3 bucket. Required.
	Bucket string
	// Region is the AWS region (e.g. "us-east-1"). Required for SigV4. Empty
	// defaults to "us-east-1".
	Region string
	// Prefix is prepended to every object key (e.g. "seance/prod/"). A
	// trailing slash is added if absent. Empty puts objects at the bucket
	// root, which works but is messy at scale.
	Prefix string
	// AccessKeyID is the AWS access key id. Required.
	AccessKeyID string
	// SecretAccessKey is the AWS secret access key. Required.
	SecretAccessKey string
	// SessionToken is the optional STS session token sent as
	// X-Amz-Security-Token. Empty for long-lived IAM-user credentials.
	SessionToken string
	// Endpoint overrides the S3 endpoint URL. Empty defaults to the public
	// AWS S3 endpoint for the configured Region. Set to point at MinIO,
	// LocalStack, Ceph RGW, or any S3-compatible API.
	Endpoint string
	// ForcePathStyle uses path-style addressing (https://endpoint/bucket/key)
	// instead of virtual-hosted style (https://bucket.endpoint/key). Required
	// for most S3-compatible servers; defaults to false (virtual-hosted) for
	// real AWS.
	ForcePathStyle bool
	// MinConfidence gates shipping: only Findings with Confidence >= this
	// value are buffered. 0 ships everything.
	MinConfidence float64
	// BatchSize is the maximum number of findings per object. 0 uses
	// defaultBatchSize.
	BatchSize int
	// BatchBytes is the maximum NDJSON body size before forcing a flush.
	// 0 uses defaultBatchBytes.
	BatchBytes int
	// FlushInterval is the maximum wall-clock time a finding may sit in the
	// buffer before being flushed. 0 uses defaultFlushInterval.
	FlushInterval time.Duration
	// BufferSize is the depth of the in-memory channel between Emit and the
	// flusher. 0 uses defaultBufferSize.
	BufferSize int
	// InsecureSkipVerify disables TLS verification on the endpoint. Useful for
	// MinIO/LocalStack with self-signed certs. Default false.
	InsecureSkipVerify bool
	// Timeout overrides the per-PUT timeout. 0 uses defaultTimeout.
	Timeout time.Duration
	// Client overrides the HTTP client (tests inject one).
	Client *http.Client
	// ErrLog receives non-fatal error lines. nil discards them.
	ErrLog io.Writer
	// Now overrides the time source (tests inject one). nil uses time.Now.
	Now func() time.Time
}

// Sink batches findings into NDJSON and PUTs them to S3 via a single
// background flusher fed by a bounded channel.
type Sink struct {
	bucket          string
	region          string
	prefix          string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	endpoint        string
	pathStyle       bool
	minConf         float64
	batchSize       int
	batchBytes      int
	flushInterval   time.Duration
	client          *http.Client
	errLog          io.Writer
	now             func() time.Time

	queue  chan output.Finding
	wg     sync.WaitGroup
	closed atomic.Bool

	putsSucceeded    atomic.Uint64
	putsFailed       atomic.Uint64
	findingsShipped  atomic.Uint64
	findingsDropped  atomic.Uint64
}

// New constructs an S3 Sink and starts its background flusher.
func New(cfg Config) (*Sink, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3: bucket is required")
	}
	if cfg.AccessKeyID == "" {
		return nil, fmt.Errorf("s3: access-key-id is required")
	}
	if cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("s3: secret-access-key is required")
	}
	if cfg.MinConfidence < 0 || cfg.MinConfidence > 1 {
		return nil, fmt.Errorf("s3: min-confidence must be between 0.0 and 1.0, got %.2f", cfg.MinConfidence)
	}

	region := cfg.Region
	if region == "" {
		region = defaultRegion
	}
	prefix := cfg.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	batchBytes := cfg.BatchBytes
	if batchBytes <= 0 {
		batchBytes = defaultBatchBytes
	}
	flushInterval := cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = defaultFlushInterval
	}
	bufferSize := cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		}
		client = &http.Client{Timeout: timeout, Transport: tr}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		// Path-style global default avoids the DNS-resolution failures that
		// virtual-hosted style hits when bucket names contain dots or when
		// the region's split-horizon hasn't propagated yet.
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", region)
	}

	s := &Sink{
		bucket:          cfg.Bucket,
		region:          region,
		prefix:          prefix,
		accessKeyID:     cfg.AccessKeyID,
		secretAccessKey: cfg.SecretAccessKey,
		sessionToken:    cfg.SessionToken,
		endpoint:        strings.TrimRight(endpoint, "/"),
		pathStyle:       cfg.ForcePathStyle,
		minConf:         cfg.MinConfidence,
		batchSize:       batchSize,
		batchBytes:      batchBytes,
		flushInterval:   flushInterval,
		client:          client,
		errLog:          cfg.ErrLog,
		now:             nowFn,
		queue:           make(chan output.Finding, bufferSize),
	}

	s.wg.Add(1)
	go s.flusher()
	return s, nil
}

// Emit implements output.Sink. Non-blocking, fail-open.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	if finding.Confidence < s.minConf {
		return nil
	}
	if s.closed.Load() {
		s.findingsDropped.Add(1)
		return nil
	}
	select {
	case s.queue <- finding:
	default:
		s.findingsDropped.Add(1)
		s.logf("séance s3: buffer full, dropped event for rule=%s repo=%s/%s (events_dropped_total=%d)",
			finding.RuleID, finding.RepoOwner, finding.RepoName, s.findingsDropped.Load())
	}
	return nil
}

// flusher drains the queue into NDJSON batches and PUTs each on a size,
// byte, or time threshold.
func (s *Sink) flusher() {
	defer s.wg.Done()

	var (
		batch    []output.Finding
		batchBuf bytes.Buffer
	)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.put(batchBuf.Bytes(), len(batch))
		batch = batch[:0]
		batchBuf.Reset()
	}

	for {
		select {
		case finding, ok := <-s.queue:
			if !ok {
				flush()
				return
			}
			line, err := json.Marshal(finding)
			if err != nil {
				s.putsFailed.Add(1)
				s.logf("séance s3: marshal error: %v", err)
				continue
			}
			batch = append(batch, finding)
			batchBuf.Write(line)
			batchBuf.WriteByte('\n')
			if len(batch) >= s.batchSize || batchBuf.Len() >= s.batchBytes {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// put PUTs a single NDJSON batch as one S3 object. Fail-open: a non-2xx
// response increments putsFailed and the batch is dropped.
func (s *Sink) put(body []byte, count int) {
	now := s.now().UTC()
	key := s.objectKey(now)

	reqURL, host, err := s.buildRequestURL(key)
	if err != nil {
		s.putsFailed.Add(1)
		s.logf("séance s3: build URL error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(body))
	if err != nil {
		s.putsFailed.Add(1)
		s.logf("séance s3: request build error: %v", err)
		return
	}
	req.Host = host
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-ndjson")

	if err := s.sign(req, body, now); err != nil {
		s.putsFailed.Add(1)
		s.logf("séance s3: sign error: %v", err)
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.putsFailed.Add(1)
		s.logf("séance s3: PUT %s failed: %v", reqURL, err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.putsFailed.Add(1)
		s.logf("séance s3: PUT %s returned %d: %s", reqURL, resp.StatusCode, truncate(string(respBody), 256))
		return
	}
	s.putsSucceeded.Add(1)
	s.findingsShipped.Add(uint64(count))
}

// objectKey renders the Hive-style partitioned key. The trailing random
// component avoids collisions across parallel séance instances writing to
// the same bucket+prefix within the same nanosecond.
func (s *Sink) objectKey(now time.Time) string {
	return fmt.Sprintf("%s%04d/%02d/%02d/%02d/seance-%d-%04d.ndjson",
		s.prefix,
		now.Year(), now.Month(), now.Day(), now.Hour(),
		now.UnixNano(),
		rand.Intn(10000),
	)
}

// buildRequestURL returns the absolute PUT URL and the Host header to send,
// honoring path-style vs virtual-hosted addressing.
func (s *Sink) buildRequestURL(key string) (string, string, error) {
	u, err := url.Parse(s.endpoint)
	if err != nil {
		return "", "", err
	}
	encodedKey := uriEncode(key, true)
	if s.pathStyle {
		fullURL := s.endpoint + "/" + s.bucket + "/" + encodedKey
		return fullURL, u.Host, nil
	}
	fullURL := u.Scheme + "://" + s.bucket + "." + u.Host + "/" + encodedKey
	return fullURL, s.bucket + "." + u.Host, nil
}

// sign applies AWS Signature Version 4 to the request, in line with
// docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html.
// Hand-rolled because pulling aws-sdk-go-v2 in for one signed PUT per minute
// would dwarf the rest of séance's dependency footprint.
func (s *Sink) sign(req *http.Request, body []byte, now time.Time) error {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := hashBytes(body)

	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}

	signedHeaderNames := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	if s.sessionToken != "" {
		signedHeaderNames = append(signedHeaderNames, "x-amz-security-token")
	}
	sort.Strings(signedHeaderNames)

	canonHeaders := strings.Builder{}
	for _, h := range signedHeaderNames {
		canonHeaders.WriteString(h)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(strings.TrimSpace(req.Header.Get(h)))
		canonHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	canonQuery := req.URL.RawQuery

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonURI,
		canonQuery,
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, s.region, defaultService, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashString(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+s.secretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, s.region)
	kService := hmacSHA256(kRegion, defaultService)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKeyID, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
	return nil
}

// Close stops accepting new findings, drains the queue (flushing any partial
// batch), and waits for the flusher to finish. Idempotent.
func (s *Sink) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.queue)
	s.wg.Wait()
	return nil
}

// Stats returns delivery counters: PUTs that succeeded (one per flushed
// batch), PUTs that failed (transport or non-2xx), individual findings
// successfully shipped, and findings dropped because the buffer was full
// or Emit was called after Close. Useful for the metrics line and tests.
func (s *Sink) Stats() (putsSucceeded, putsFailed, findingsShipped, findingsDropped uint64) {
	return s.putsSucceeded.Load(), s.putsFailed.Load(),
		s.findingsShipped.Load(), s.findingsDropped.Load()
}

func (s *Sink) logf(format string, args ...any) {
	if s.errLog == nil {
		return
	}
	fmt.Fprintln(s.errLog, fmt.Sprintf(format, args...))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hashBytes(b []byte) string {
	if len(b) == 0 {
		return emptyPayloadHash
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// uriEncode implements RFC3986 percent-encoding the way SigV4 demands —
// see docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html.
// path=true preserves '/'.
func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && path:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
