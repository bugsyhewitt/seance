package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// TestEmitPostsCorrectBodyAndHeaders verifies that a Finding is delivered as a
// JSON POST with the configured Authorization header and a JSON content type,
// and that the body round-trips to the original Finding.
func TestEmitPostsCorrectBodyAndHeaders(t *testing.T) {
	var (
		gotMethod  string
		gotAuth    string
		gotCT      string
		gotBody    []byte
		gotFinding output.Finding
	)
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		_ = json.Unmarshal(gotBody, &gotFinding)
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	s := New(Config{
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer s3cr3t-token"},
	})

	want := sampleFinding()
	if err := s.Emit(context.Background(), want); err != nil {
		t.Fatalf("Emit returned error: %v", err)
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
	if gotAuth != "Bearer s3cr3t-token" {
		t.Errorf("Authorization = %q, want Bearer s3cr3t-token", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotFinding.RuleID != want.RuleID || gotFinding.Redacted != want.Redacted ||
		gotFinding.RepoOwner != want.RepoOwner || gotFinding.Confidence != want.Confidence {
		t.Errorf("decoded finding = %+v, want %+v", gotFinding, want)
	}

	sent, failed, dropped := s.Stats()
	if sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d, want 1/0/0", sent, failed, dropped)
	}
}

// TestNoRawSecretLeaksIntoBody asserts the POST body contains only redacted
// material — the never-emit-raw-secrets invariant. The redacted mask is present;
// a hypothetical raw value never appears because Finding has no raw field.
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

	s := New(Config{URL: srv.URL})
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if bytes.Contains(gotBody, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatal("raw secret leaked into webhook body")
	}
	if !bytes.Contains(gotBody, []byte("AKIA********************WXYZ")) {
		t.Errorf("redacted value missing from body: %s", gotBody)
	}
}

// TestMinConfidenceGating verifies that findings below the threshold are not sent.
func TestMinConfidenceGating(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(Config{URL: srv.URL, MinConfidence: 0.85})

	low := sampleFinding()
	low.Confidence = 0.5
	high := sampleFinding()
	high.Confidence = 0.95

	_ = s.Emit(context.Background(), low)
	_ = s.Emit(context.Background(), high)
	_ = s.Close()

	if got := received.Load(); got != 1 {
		t.Errorf("server received %d posts, want 1 (only the high-confidence finding)", got)
	}
	sent, _, _ := s.Stats()
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
}

// TestNonBlockingOn5xx verifies a 500 response does not error Emit, does not
// kill the run, and is counted as a failure while the run continues.
func TestNonBlockingOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var errLog bytes.Buffer
	s := New(Config{URL: srv.URL, ErrLog: &errLog})

	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit returned error on 5xx (must fail open): %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sent, failed, dropped := s.Stats()
	if sent != 0 {
		t.Errorf("sent = %d, want 0", sent)
	}
	if failed != 3 {
		t.Errorf("failed = %d, want 3", failed)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	if errLog.Len() == 0 {
		t.Error("expected non-2xx to be logged to stderr")
	}
}

// TestNonBlockingOnDeadEndpoint verifies a transport error (connection refused)
// fails open and never blocks the pipeline.
func TestNonBlockingOnDeadEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so the endpoint is dead

	s := New(Config{URL: url, Timeout: 200 * time.Millisecond})
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

// TestQueueOverflowDropsWithoutBlocking verifies that a slow endpoint causes
// overflow findings to be dropped (and counted) rather than blocking Emit.
func TestQueueOverflowDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release // block the worker until the test releases it
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Queue size 1 plus the one in-flight request the worker is blocked on.
	s := New(Config{URL: srv.URL, QueueSize: 1})

	// Give the worker a moment to pick up the first finding and block on the
	// server, so the queue can actually fill.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// First Emit -> picked up by worker, blocks on server.
		_ = s.Emit(context.Background(), sampleFinding())
		// Wait until the worker is actually blocked on the server.
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
		// Now flood: these must not block even though the worker is stuck.
		for i := 0; i < 100; i++ {
			_ = s.Emit(context.Background(), sampleFinding())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked — pipeline would stall on a slow endpoint")
	}
	wg.Wait()

	// Release the worker and let it drain.
	close(release)
	_ = s.Close()

	_, _, dropped := s.Stats()
	if dropped == 0 {
		t.Error("expected some findings to be dropped on queue overflow")
	}
}

// TestCloseIsIdempotent verifies Close can be called more than once safely.
func TestCloseIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(Config{URL: srv.URL})
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Emit after close must not panic and must drop.
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit after Close: %v", err)
	}
	_, _, dropped := s.Stats()
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (emit after close)", dropped)
	}
}
