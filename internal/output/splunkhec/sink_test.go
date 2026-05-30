package splunkhec

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

func TestNewRejectsEmptyURL(t *testing.T) {
	if _, err := New(Config{Token: "x"}); err == nil {
		t.Fatal("expected error on empty URL")
	}
}

func TestNewRejectsEmptyToken(t *testing.T) {
	if _, err := New(Config{URL: "http://x"}); err == nil {
		t.Fatal("expected error on empty token")
	}
}

func TestNewRejectsBadMinConfidence(t *testing.T) {
	if _, err := New(Config{URL: "http://x", Token: "y", MinConfidence: 1.5}); err == nil {
		t.Fatal("expected error on min-confidence > 1")
	}
	if _, err := New(Config{URL: "http://x", Token: "y", MinConfidence: -0.1}); err == nil {
		t.Fatal("expected error on min-confidence < 0")
	}
}

// TestEmitPostsHECEnvelope verifies the POST carries the HEC Authorization
// header, the JSON content type, and a wire-correct HEC envelope wrapping the
// redacted Finding under "event".
func TestEmitPostsHECEnvelope(t *testing.T) {
	var (
		gotMethod string
		gotAuth   string
		gotCT     string
		gotBody   []byte
	)
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
		close(done)
	}))
	defer srv.Close()

	s, err := New(Config{
		URL:        srv.URL,
		Token:      "hec-token-xyz",
		Index:      "seance_idx",
		Source:     "seance-test",
		SourceType: "seance:finding:test",
		Host:       "alfred",
	})
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
	if gotAuth != "Splunk hec-token-xyz" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Splunk hec-token-xyz")
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}

	var env struct {
		Time       float64        `json:"time"`
		Host       string         `json:"host"`
		Source     string         `json:"source"`
		SourceType string         `json:"sourcetype"`
		Index      string         `json:"index"`
		Event      output.Finding `json:"event"`
	}
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, gotBody)
	}
	if env.Host != "alfred" {
		t.Errorf("envelope host = %q, want alfred", env.Host)
	}
	if env.Source != "seance-test" {
		t.Errorf("envelope source = %q, want seance-test", env.Source)
	}
	if env.SourceType != "seance:finding:test" {
		t.Errorf("envelope sourcetype = %q, want seance:finding:test", env.SourceType)
	}
	if env.Index != "seance_idx" {
		t.Errorf("envelope index = %q, want seance_idx", env.Index)
	}
	if env.Event.RuleID != want.RuleID || env.Event.Redacted != want.Redacted {
		t.Errorf("envelope event = %+v, want %+v", env.Event, want)
	}
	// HEC time is epoch seconds (float). Sample finding's timestamp is
	// 1700000000s exactly, so the float must match within FP tolerance.
	if env.Time < 1699999999.9 || env.Time > 1700000000.1 {
		t.Errorf("envelope time = %v, want ~1700000000.0", env.Time)
	}

	sent, failed, dropped := s.Stats()
	if sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d, want 1/0/0", sent, failed, dropped)
	}
}

// TestDefaultSourceAndSourceType verifies the documented defaults survive an
// otherwise-bare Config — security teams shouldn't have to set them just to
// get a working stream.
func TestDefaultSourceAndSourceType(t *testing.T) {
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

	s, err := New(Config{URL: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	var env map[string]any
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env["source"] != "seance" {
		t.Errorf("default source = %v, want seance", env["source"])
	}
	if env["sourcetype"] != "seance:finding" {
		t.Errorf("default sourcetype = %v, want seance:finding", env["sourcetype"])
	}
	if _, present := env["host"]; present {
		t.Errorf("empty Host should be omitted from envelope, got %v", env["host"])
	}
	if _, present := env["index"]; present {
		t.Errorf("empty Index should be omitted from envelope, got %v", env["index"])
	}
}

// TestNoRawSecretLeaksIntoBody asserts the HEC body carries only redacted
// material — the never-emit-raw-secrets invariant for the HEC channel.
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

	s, _ := New(Config{URL: srv.URL, Token: "tok"})
	_ = s.Emit(context.Background(), sampleFinding())
	<-done
	_ = s.Close()

	if bytes.Contains(gotBody, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatal("raw secret leaked into HEC body")
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

	s, _ := New(Config{URL: srv.URL, Token: "tok", MinConfidence: 0.85})

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

func TestNonBlockingOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var errLog bytes.Buffer
	s, _ := New(Config{URL: srv.URL, Token: "tok", ErrLog: &errLog})

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

	s, _ := New(Config{URL: url, Token: "tok", Timeout: 200 * time.Millisecond})
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

// TestQueueOverflowDropsWithoutBlocking — pipeline must never stall on a slow HEC.
func TestQueueOverflowDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, Token: "tok", QueueSize: 1})

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
		t.Fatal("Emit blocked — pipeline would stall on a slow HEC")
	}
	wg.Wait()

	close(release)
	_ = s.Close()

	_, _, dropped := s.Stats()
	if dropped == 0 {
		t.Error("expected some events to be dropped on queue overflow")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := New(Config{URL: srv.URL, Token: "tok"})
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
