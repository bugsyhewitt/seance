package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

func sampleFinding() output.Finding {
	return output.Finding{
		RuleID:     "aws-access-key",
		RuleDesc:   "AWS access key id",
		Provider:   "github",
		RepoOwner:  "octocat",
		RepoName:   "hello-world",
		CommitSHA:  "deadbeef",
		FilePath:   ".env",
		LineNumber: 12,
		Redacted:   "AKIA********************WXYZ",
		Confidence: 0.9,
		Tags:       []string{"aws", "cloud"},
		Timestamp:  time.Unix(1700000000, 0).UTC(),
	}
}

func baseConfig(t *testing.T, srv *httptest.Server) Config {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Config{
		Bucket:          "seance-test-bucket",
		Region:          "us-east-1",
		AccessKeyID:     "AKIATESTACCESSKEY",
		SecretAccessKey: "test-secret-key",
		Endpoint:        u.Scheme + "://" + u.Host,
		ForcePathStyle:  true,
		BatchSize:       1, // flush on every Emit so tests don't depend on a ticker
		FlushInterval:   1 * time.Hour,
	}
}

func TestNewRejectsEmptyBucket(t *testing.T) {
	if _, err := New(Config{AccessKeyID: "x", SecretAccessKey: "y"}); err == nil {
		t.Fatal("expected error on empty bucket")
	}
}

func TestNewRejectsEmptyCredentials(t *testing.T) {
	if _, err := New(Config{Bucket: "b", SecretAccessKey: "y"}); err == nil {
		t.Fatal("expected error on empty access-key-id")
	}
	if _, err := New(Config{Bucket: "b", AccessKeyID: "x"}); err == nil {
		t.Fatal("expected error on empty secret-access-key")
	}
}

func TestNewRejectsBadMinConfidence(t *testing.T) {
	cfg := Config{Bucket: "b", AccessKeyID: "x", SecretAccessKey: "y", MinConfidence: 1.5}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error on min-confidence > 1")
	}
	cfg.MinConfidence = -0.1
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error on min-confidence < 0")
	}
}

// TestEmitPutsNDJSONObject verifies the PUT carries SigV4 auth, the NDJSON
// content type, a path-style URL targeting the right bucket, and a body whose
// single line is the redacted Finding as JSON.
func TestEmitPutsNDJSONObject(t *testing.T) {
	var (
		gotMethod string
		gotAuth   string
		gotCT     string
		gotPath   string
		gotBody   []byte
		gotSha    string
	)
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		gotSha = r.Header.Get("X-Amz-Content-Sha256")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	cfg := baseConfig(t, srv)
	cfg.Prefix = "seance/prod"
	cfg.Now = func() time.Time { return time.Date(2026, 5, 30, 14, 0, 0, 0, time.UTC) }

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := sampleFinding()
	if err := s.Emit(context.Background(), want); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the PUT")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKIATESTACCESSKEY/20260530/us-east-1/s3/aws4_request") {
		t.Errorf("Authorization = %q, missing SigV4 credential scope", gotAuth)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") {
		t.Errorf("Authorization = %q, missing expected SignedHeaders", gotAuth)
	}
	if !strings.Contains(gotAuth, "Signature=") {
		t.Errorf("Authorization = %q, missing Signature=", gotAuth)
	}
	if gotCT != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", gotCT)
	}
	if gotSha == "" {
		t.Error("missing X-Amz-Content-Sha256")
	}
	if !strings.HasPrefix(gotPath, "/seance-test-bucket/seance/prod/2026/05/30/14/seance-") {
		t.Errorf("path = %q, want Hive-partitioned key under /seance-test-bucket/seance/prod/2026/05/30/14/", gotPath)
	}
	if !strings.HasSuffix(gotPath, ".ndjson") {
		t.Errorf("path = %q, want .ndjson suffix", gotPath)
	}

	lines := bytes.Split(bytes.TrimRight(gotBody, "\n"), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("body lines = %d, want 1 (body=%q)", len(lines), gotBody)
	}
	var got output.Finding
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("decode line: %v (line=%s)", err, lines[0])
	}
	if got.RuleID != want.RuleID || got.Redacted != want.Redacted {
		t.Errorf("decoded = %+v, want rule=%s redacted=%s", got, want.RuleID, want.Redacted)
	}

	puts, failed, shipped, dropped := s.Stats()
	if puts != 1 || failed != 0 || shipped != 1 || dropped != 0 {
		t.Errorf("stats puts=%d failed=%d shipped=%d dropped=%d, want 1/0/1/0", puts, failed, shipped, dropped)
	}
}

// TestBatchingByCount verifies multiple findings collapse into one NDJSON
// object whose lines are the individual findings — the cost-discipline whole
// point of the sink.
func TestBatchingByCount(t *testing.T) {
	var gotBody []byte
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	cfg := baseConfig(t, srv)
	cfg.BatchSize = 3
	cfg.FlushInterval = 1 * time.Hour

	s, _ := New(cfg)
	for i := 0; i < 3; i++ {
		_ = s.Emit(context.Background(), sampleFinding())
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the batched PUT")
	}
	_ = s.Close()

	lines := bytes.Split(bytes.TrimRight(gotBody, "\n"), []byte{'\n'})
	if len(lines) != 3 {
		t.Errorf("body lines = %d, want 3 (one PUT carries the whole batch)", len(lines))
	}
	puts, _, shipped, _ := s.Stats()
	if puts != 1 || shipped != 3 {
		t.Errorf("puts=%d shipped=%d, want 1/3", puts, shipped)
	}
}

// TestFlushOnClose verifies a partial batch sitting in the buffer when Close
// runs still PUTs — otherwise a short run loses every finding.
func TestFlushOnClose(t *testing.T) {
	var received atomic.Int64
	var bodyLines atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte{'\n'})
		bodyLines.Add(int64(len(lines)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := baseConfig(t, srv)
	cfg.BatchSize = 100   // never reach the size threshold
	cfg.FlushInterval = 1 * time.Hour

	s, _ := New(cfg)
	for i := 0; i < 5; i++ {
		_ = s.Emit(context.Background(), sampleFinding())
	}
	_ = s.Close()

	if received.Load() != 1 {
		t.Errorf("PUTs received = %d, want 1 (a Close flush)", received.Load())
	}
	if bodyLines.Load() != 5 {
		t.Errorf("body lines = %d, want 5", bodyLines.Load())
	}
}

// TestNoRawSecretLeaksIntoBody asserts the object body carries only redacted
// material — the never-emit-raw-secrets invariant for the S3 channel.
func TestNoRawSecretLeaksIntoBody(t *testing.T) {
	var gotBody []byte
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	s, _ := New(baseConfig(t, srv))
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if bytes.Contains(gotBody, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatal("raw secret leaked into S3 body")
	}
	if !bytes.Contains(gotBody, []byte("AKIA********************WXYZ")) {
		t.Errorf("redacted value missing from body: %s", gotBody)
	}
}

func TestMinConfidenceGating(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := baseConfig(t, srv)
	cfg.MinConfidence = 0.85
	s, _ := New(cfg)

	low := sampleFinding()
	low.Confidence = 0.5
	high := sampleFinding()
	high.Confidence = 0.95

	_ = s.Emit(context.Background(), low)
	_ = s.Emit(context.Background(), high)
	_ = s.Close()

	if got := received.Load(); got != 1 {
		t.Errorf("server received %d PUTs, want 1 (only high confidence)", got)
	}
	puts, _, shipped, _ := s.Stats()
	if puts != 1 || shipped != 1 {
		t.Errorf("puts=%d shipped=%d, want 1/1", puts, shipped)
	}
}

func TestNonBlockingOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var errLog bytes.Buffer
	cfg := baseConfig(t, srv)
	cfg.ErrLog = &errLog
	s, _ := New(cfg)

	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit must fail open on 5xx, got: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	puts, failed, _, _ := s.Stats()
	if puts != 0 {
		t.Errorf("succeeded = %d, want 0", puts)
	}
	if failed == 0 {
		t.Errorf("failed = %d, want > 0", failed)
	}
	if errLog.Len() == 0 {
		t.Error("expected non-2xx to be logged to stderr")
	}
}

func TestNonBlockingOnDeadEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := srv.URL
	srv.Close()

	cfg := Config{
		Bucket:          "b",
		Region:          "us-east-1",
		AccessKeyID:     "x",
		SecretAccessKey: "y",
		Endpoint:        endpoint,
		ForcePathStyle:  true,
		BatchSize:       1,
		Timeout:         200 * time.Millisecond,
	}
	s, _ := New(cfg)
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit must fail open on dead endpoint, got: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, failed, _, _ := s.Stats()
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
}

// TestBufferOverflowDropsWithoutBlocking — pipeline must never stall on a slow bucket.
func TestBufferOverflowDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := baseConfig(t, srv)
	cfg.BufferSize = 1
	cfg.BatchSize = 1
	s, _ := New(cfg)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Emit(context.Background(), sampleFinding())
		deadline := time.After(2 * time.Second)
		for hits.Load() == 0 {
			select {
			case <-deadline:
				t.Error("flusher never reached the server")
				close(done)
				return
			default:
				time.Sleep(time.Millisecond)
			}
		}
		for i := 0; i < 100; i++ {
			_ = s.Emit(context.Background(), sampleFinding())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked — pipeline would stall on a slow bucket")
	}
	wg.Wait()

	close(release)
	_ = s.Close()

	_, _, _, dropped := s.Stats()
	if dropped == 0 {
		t.Error("expected some events to be dropped on buffer overflow")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := New(baseConfig(t, srv))
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit after Close: %v", err)
	}
	_, _, _, dropped := s.Stats()
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (emit after close)", dropped)
	}
}

// TestSessionTokenHeader verifies STS credentials propagate the session
// token to the request — otherwise short-lived role credentials silently
// fail with 403 from S3.
func TestSessionTokenHeader(t *testing.T) {
	var gotToken string
	var gotAuth string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Amz-Security-Token")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	cfg := baseConfig(t, srv)
	cfg.SessionToken = "FQoDYXdzEJr//////////wEaDS"

	s, _ := New(cfg)
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotToken != "FQoDYXdzEJr//////////wEaDS" {
		t.Errorf("X-Amz-Security-Token = %q, want session token", gotToken)
	}
	if !strings.Contains(gotAuth, "x-amz-security-token") {
		t.Errorf("session-token Authorization SignedHeaders = %q, missing x-amz-security-token", gotAuth)
	}
}

// TestVirtualHostedURL verifies the non-path-style code path (the AWS default)
// builds bucket.endpoint URLs and sets Host accordingly.
func TestVirtualHostedURL(t *testing.T) {
	// Can't actually hit a server because the test server's host doesn't
	// have a wildcard cert / DNS for bucket.<host>. Just sanity-check the
	// URL builder directly.
	s := &Sink{
		bucket:    "my-bucket",
		endpoint:  "https://s3.us-east-1.amazonaws.com",
		pathStyle: false,
	}
	url, host, err := s.buildRequestURL("seance/2026/05/30/14/seance-1.ndjson")
	if err != nil {
		t.Fatalf("buildRequestURL: %v", err)
	}
	if url != "https://my-bucket.s3.us-east-1.amazonaws.com/seance/2026/05/30/14/seance-1.ndjson" {
		t.Errorf("virtual-hosted URL = %q", url)
	}
	if host != "my-bucket.s3.us-east-1.amazonaws.com" {
		t.Errorf("virtual-hosted Host = %q", host)
	}

	s.pathStyle = true
	url, host, err = s.buildRequestURL("seance/2026/05/30/14/seance-1.ndjson")
	if err != nil {
		t.Fatalf("buildRequestURL path-style: %v", err)
	}
	if url != "https://s3.us-east-1.amazonaws.com/my-bucket/seance/2026/05/30/14/seance-1.ndjson" {
		t.Errorf("path-style URL = %q", url)
	}
	if host != "s3.us-east-1.amazonaws.com" {
		t.Errorf("path-style Host = %q", host)
	}
}

// TestObjectKeyPartitioning verifies the Hive-style partition layout so
// Athena/Glue partition pruning Just Works against the bucket.
func TestObjectKeyPartitioning(t *testing.T) {
	s := &Sink{prefix: "seance/prod/"}
	tm := time.Date(2026, 5, 30, 14, 22, 33, 0, time.UTC)
	key := s.objectKey(tm)
	if !strings.HasPrefix(key, "seance/prod/2026/05/30/14/seance-") {
		t.Errorf("key = %q, want Hive partition seance/prod/YYYY/MM/DD/HH/ prefix", key)
	}
	if !strings.HasSuffix(key, ".ndjson") {
		t.Errorf("key = %q, want .ndjson extension", key)
	}
}
