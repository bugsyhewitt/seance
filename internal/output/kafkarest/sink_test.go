package kafkarest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// TestNewRejectsEmptyURL verifies that New returns an error when no URL is set.
func TestNewRejectsEmptyURL(t *testing.T) {
	if _, err := New(Config{Topic: "t"}); err == nil {
		t.Fatal("expected error on empty URL")
	}
}

// TestNewRejectsEmptyTopic verifies that New returns an error when no topic is set.
func TestNewRejectsEmptyTopic(t *testing.T) {
	if _, err := New(Config{URL: "http://x"}); err == nil {
		t.Fatal("expected error on empty Topic")
	}
}

// TestNewRejectsBadMinConfidence verifies out-of-range min-confidence is rejected.
func TestNewRejectsBadMinConfidence(t *testing.T) {
	if _, err := New(Config{URL: "http://x", Topic: "t", MinConfidence: 1.5}); err == nil {
		t.Fatal("expected error on min-confidence > 1")
	}
	if _, err := New(Config{URL: "http://x", Topic: "t", MinConfidence: -0.1}); err == nil {
		t.Fatal("expected error on min-confidence < 0")
	}
}

// TestTopicURLConstruction verifies the topic URL is derived from the base URL.
func TestTopicURLConstruction(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"offsets":[{"partition":0,"offset":0}]}`))
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, Topic: "seance-findings"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	_ = s.Close()

	if gotPath != "/topics/seance-findings" {
		t.Errorf("topic path = %q, want /topics/seance-findings", gotPath)
	}
}

// TestTopicURLTrailingSlash verifies that a trailing slash in the base URL is
// stripped so the topic path is always canonical.
func TestTopicURLTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL + "/", Topic: "findings"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	_ = s.Close()

	if gotPath != "/topics/findings" {
		t.Errorf("topic path = %q, want /topics/findings", gotPath)
	}
}

// TestEmitPostsCorrectEnvelope verifies the POST body matches the REST Proxy
// v2 produce schema: {"records": [{"value": <Finding>}]}.
func TestEmitPostsCorrectEnvelope(t *testing.T) {
	var (
		gotMethod string
		gotCT     string
		gotBody   []byte
	)
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"offsets":[{"partition":0,"offset":0}]}`))
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, Topic: "seance-findings"})
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
		t.Fatal("server never received the POST")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotCT != contentType {
		t.Errorf("Content-Type = %q, want %q", gotCT, contentType)
	}

	var envelope struct {
		Records []struct {
			Value output.Finding `json:"value"`
		} `json:"records"`
	}
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, gotBody)
	}
	if len(envelope.Records) != 1 {
		t.Fatalf("records count = %d, want 1", len(envelope.Records))
	}
	got := envelope.Records[0].Value
	if got.RuleID != want.RuleID || got.Redacted != want.Redacted {
		t.Errorf("envelope value = %+v, want %+v", got, want)
	}

	sent, failed, dropped := s.Stats()
	if sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d, want 1/0/0", sent, failed, dropped)
	}
}

// TestBearerAuthTakesPrecedence verifies that when APIKey is set it is sent as
// "Authorization: Bearer <key>" and Basic auth is not added.
func TestBearerAuthTakesPrecedence(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{
		URL:      srv.URL,
		Topic:    "t",
		APIKey:   "mykey",
		Username: "user",
		Password: "pass",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotAuth != "Bearer mykey" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer mykey")
	}
}

// TestBasicAuth verifies that HTTP Basic auth is sent when Username and Password
// are set (and no APIKey is present).
func TestBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{
		URL:      srv.URL,
		Topic:    "t",
		Username: "alice",
		Password: "s3cret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotUser != "alice" || gotPass != "s3cret" {
		t.Errorf("basic auth user=%q pass=%q, want alice/s3cret", gotUser, gotPass)
	}
}

// TestNoAuthWhenUnset verifies that no Authorization header is set when
// neither APIKey nor Username/Password are configured.
func TestNoAuthWhenUnset(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, Topic: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

// TestNoRawSecretLeak asserts the POST body contains only the redacted value —
// the never-emit-raw-secrets invariant for the Kafka REST channel.
func TestNoRawSecretLeak(t *testing.T) {
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

	s, _ := New(Config{URL: srv.URL, Topic: "t"})
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if bytes.Contains(gotBody, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatal("raw secret leaked into Kafka REST body")
	}
	if !bytes.Contains(gotBody, []byte("AKIA********************WXYZ")) {
		t.Errorf("redacted value missing from body: %s", gotBody)
	}
}

// TestMinConfidenceGating verifies that findings below the threshold are not
// shipped to the REST Proxy.
func TestMinConfidenceGating(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, Topic: "t", MinConfidence: 0.85})

	low := sampleFinding()
	low.Confidence = 0.5
	high := sampleFinding()
	high.Confidence = 0.95

	_ = s.Emit(context.Background(), low)
	_ = s.Emit(context.Background(), high)
	_ = s.Close()

	if got := received.Load(); got != 1 {
		t.Errorf("server received %d posts, want 1 (only high confidence)", got)
	}
	sent, _, _ := s.Stats()
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
}

// TestNonBlockingOn5xx verifies that a 5xx response is logged but does not
// propagate an error to the caller — fail-open contract.
func TestNonBlockingOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var errLog bytes.Buffer
	s, _ := New(Config{URL: srv.URL, Topic: "t", ErrLog: &errLog})

	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit must fail open on 5xx, got: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sent, failed, dropped := s.Stats()
	if sent != 0 || failed != 3 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d, want 0/3/0", sent, failed, dropped)
	}
	if errLog.Len() == 0 {
		t.Error("expected non-2xx to be logged to errLog")
	}
}

// TestNonBlockingOnDeadEndpoint verifies that a dead endpoint is counted as
// failed, not returned as an error — fail-open contract.
func TestNonBlockingOnDeadEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	s, _ := New(Config{URL: url, Topic: "t", Timeout: 200 * time.Millisecond})
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit must fail open on dead endpoint, got: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, failed, _ := s.Stats()
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
}

// TestQueueOverflowDropsWithoutBlocking verifies that a slow REST Proxy does
// not block the scan pipeline — overflow is dropped and counted, not queued.
func TestQueueOverflowDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, Topic: "t", QueueSize: 1})

	done := make(chan struct{})
	go func() {
		_ = s.Emit(context.Background(), sampleFinding())
		// Wait for the worker to start processing (hitting the server).
		deadline := time.After(2 * time.Second)
		for hits.Load() == 0 {
			select {
			case <-deadline:
				t.Error("worker never reached the server")
				close(done)
				return
			default:
				time.Sleep(time.Millisecond)
			}
		}
		// Flood the queue while the worker is blocked in the server handler.
		for i := 0; i < 100; i++ {
			_ = s.Emit(context.Background(), sampleFinding())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked — pipeline would stall on a slow REST Proxy")
	}

	close(release)
	_ = s.Close()

	_, _, dropped := s.Stats()
	if dropped == 0 {
		t.Error("expected some events to be dropped on queue overflow")
	}
}

// TestCloseIsIdempotent verifies that calling Close twice does not panic or
// return an error, and that Emit after Close drops the finding (fail-open).
func TestCloseIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, Topic: "t"})
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit after Close: %v", err)
	}
	_, _, dropped := s.Stats()
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (emit after close)", dropped)
	}
}
