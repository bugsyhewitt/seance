package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// --- construction validation -------------------------------------------------

func TestNewRejectsEmptyURL(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error on empty URL")
	}
}

func TestNewRejectsBadMinConfidence(t *testing.T) {
	if _, err := New(Config{URL: "http://x", MinConfidence: 1.5}); err == nil {
		t.Fatal("expected error on min-confidence > 1")
	}
	if _, err := New(Config{URL: "http://x", MinConfidence: -0.1}); err == nil {
		t.Fatal("expected error on min-confidence < 0")
	}
}

func TestNewRejectsUsernameWithoutPassword(t *testing.T) {
	if _, err := New(Config{URL: "http://x", Username: "elastic"}); err == nil {
		t.Fatal("expected error when username is set but password is empty")
	}
}

// --- basic indexing ----------------------------------------------------------

// TestEmitIndexesDocument verifies the POST hits the correct endpoint path,
// carries Content-Type: application/json, and the body is valid JSON
// containing the redacted Finding fields.
func TestEmitIndexesDocument(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotCT     string
		gotBody   []byte
	)
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":"created","_id":"abc"}`))
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, Index: "seance-test"})
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
	if !strings.HasPrefix(gotPath, "/seance-test/_doc") {
		t.Errorf("path = %q, want /seance-test/_doc...", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}

	var doc output.Finding
	if err := json.Unmarshal(gotBody, &doc); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, gotBody)
	}
	if doc.RuleID != want.RuleID || doc.Redacted != want.Redacted {
		t.Errorf("doc = %+v, want %+v", doc, want)
	}

	sent, failed, dropped := s.Stats()
	if sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d, want 1/0/0", sent, failed, dropped)
	}
}

// TestDefaultIndexUsed verifies "seance-findings" is used when Config.Index is
// empty.
func TestDefaultIndexUsed(t *testing.T) {
	var gotPath string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if !strings.HasPrefix(gotPath, "/seance-findings/_doc") {
		t.Errorf("path = %q, want /seance-findings/_doc...", gotPath)
	}
}

// --- authentication ----------------------------------------------------------

func TestApiKeyAuthentication(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, ApiKey: "my-api-key-value"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotAuth != "ApiKey my-api-key-value" {
		t.Errorf("Authorization = %q, want \"ApiKey my-api-key-value\"", gotAuth)
	}
}

func TestBasicAuthentication(t *testing.T) {
	var gotUser, gotPass string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusCreated)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL, Username: "elastic", Password: "changeme"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotUser != "elastic" || gotPass != "changeme" {
		t.Errorf("basic auth user=%q pass=%q, want elastic/changeme", gotUser, gotPass)
	}
}

func TestApiKeyTakesPrecedenceOverBasicAuth(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{
		URL:      srv.URL,
		ApiKey:   "api-key-wins",
		Username: "elastic",
		Password: "changeme",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if !strings.HasPrefix(gotAuth, "ApiKey ") {
		t.Errorf("Authorization = %q, want ApiKey prefix (should take precedence over basic)", gotAuth)
	}
}

func TestNoAuthHeaderWhenAnonymous(t *testing.T) {
	var gotAuth string
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty (anonymous)", gotAuth)
	}
}

// --- never-emit-raw-secrets invariant ----------------------------------------

// TestNoRawSecretLeaksIntoBody asserts the indexed document body never carries
// raw secret material — only the redacted representation.
func TestNoRawSecretLeaksIntoBody(t *testing.T) {
	var gotBody []byte
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusCreated)
		close(done)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL})
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if bytes.Contains(gotBody, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatal("raw secret leaked into indexed document body")
	}
	if !bytes.Contains(gotBody, []byte("AKIA********************WXYZ")) {
		t.Errorf("redacted value missing from body: %s", gotBody)
	}
}

// --- confidence gating -------------------------------------------------------

func TestMinConfidenceGating(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, MinConfidence: 0.85})

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

// --- fail-open / resilience --------------------------------------------------

func TestNonBlockingOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var errLog bytes.Buffer
	s, _ := New(Config{URL: srv.URL, ErrLog: &errLog})

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
		t.Error("expected non-2xx to be logged to stderr")
	}
}

func TestNonBlockingOnDeadEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	s, _ := New(Config{URL: url, Timeout: 200 * time.Millisecond})
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

// TestQueueOverflowDropsWithoutBlocking — pipeline must never stall on a slow
// Elasticsearch cluster.
func TestQueueOverflowDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, QueueSize: 1})

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
				t.Error("worker never reached the server")
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
		t.Fatal("Emit blocked — pipeline would stall on a slow Elasticsearch cluster")
	}
	wg.Wait()

	close(release)
	_ = s.Close()

	_, _, dropped := s.Stats()
	if dropped == 0 {
		t.Error("expected some events to be dropped on queue overflow")
	}
}

// --- Close idempotency -------------------------------------------------------

func TestCloseIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL})
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
