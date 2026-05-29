package webhookrecv

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

const testSecret = "s3cr3t-webhook-key"

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// startProvider binds the provider to an ephemeral port, returns the base URL,
// the live event channel, and a cancel func. It waits until the listener is
// actually accepting connections so tests are not racy.
func startProvider(t *testing.T, p *Provider) (baseURL string, events <-chan ingestion.CommitEvent, errs <-chan error, cancel context.CancelFunc) {
	t.Helper()
	// Reserve a free port, then hand the address to the provider.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	p.cfg.Addr = addr

	ctx, cancel := context.WithCancel(context.Background())
	ev, er := p.Stream(ctx)

	url := "http://" + addr + p.cfg.Path
	// Wait for the server to come up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if derr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return url, ev, er, cancel
}

func post(t *testing.T, url, event, signature string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-GitHub-Event", event)
	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestPushWithCommitsEmitsEventsAndFiles(t *testing.T) {
	p := New("", "/webhook", testSecret)
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{
		"ref":"refs/heads/main",
		"before":"aaa","after":"bbb",
		"repository":{"full_name":"acme/widgets"},
		"pusher":{"name":"dev"},
		"commits":[
			{"id":"c1","message":"add config","author":{"name":"Dev","email":"d@acme.io"},"added":[".env"],"modified":["app.go"],"removed":[]},
			{"id":"c2","message":"tweak","author":{"name":"Dev","email":"d@acme.io"},"modified":["main.go"]}
		]
	}`)
	resp := post(t, url, "push", sign(testSecret, body), body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	got := drain(t, events, 2)
	if len(got) != 2 {
		t.Fatalf("emitted %d events, want 2", len(got))
	}
	if got[0].Provider != "webhook" {
		t.Errorf("provider = %q, want webhook", got[0].Provider)
	}
	if got[0].RepoOwner != "acme" || got[0].RepoName != "widgets" {
		t.Errorf("repo = %s/%s, want acme/widgets", got[0].RepoOwner, got[0].RepoName)
	}
	if got[0].CommitSHA != "c1" {
		t.Errorf("sha = %q, want c1", got[0].CommitSHA)
	}
	if !got[0].FilesKnown {
		t.Errorf("FilesKnown = false, want true (commits array present)")
	}
	if len(got[0].Files) != 2 {
		t.Errorf("files = %d, want 2 (.env added, app.go modified)", len(got[0].Files))
	}
	if atomic.LoadUint64(&p.Metrics.CommitsEmitted) != 2 {
		t.Errorf("CommitsEmitted = %d, want 2", p.Metrics.CommitsEmitted)
	}
	if atomic.LoadUint64(&p.Metrics.PushEventsReceived) != 1 {
		t.Errorf("PushEventsReceived = %d, want 1", p.Metrics.PushEventsReceived)
	}
}

func TestPushWithoutCommitsFallsBackToHeadSHA(t *testing.T) {
	p := New("", "", "") // no secret, default path
	if p.Path() != "/webhook" {
		t.Fatalf("default path = %q, want /webhook", p.Path())
	}
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{
		"ref":"refs/heads/main",
		"before":"aaa","after":"deadbeef",
		"repository":{"full_name":"acme/widgets"},
		"pusher":{"name":"dev"}
	}`)
	resp := post(t, url, "push", "", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no secret means no verification)", resp.StatusCode)
	}
	resp.Body.Close()

	got := drain(t, events, 1)
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	if got[0].CommitSHA != "deadbeef" {
		t.Errorf("sha = %q, want deadbeef (head fallback)", got[0].CommitSHA)
	}
	if got[0].FilesKnown {
		t.Errorf("FilesKnown = true, want false (no commits array)")
	}
}

func TestForcePushEmitsFlaggedEventWithBeforeSHA(t *testing.T) {
	p := New("", "/webhook", testSecret)
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{
		"ref":"refs/heads/main",
		"before":"old111","after":"new222","forced":true,
		"created":false,"deleted":false,
		"repository":{"full_name":"acme/widgets"},
		"pusher":{"name":"panicked-dev"}
	}`)
	resp := post(t, url, "push", sign(testSecret, body), body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	got := drain(t, events, 1)
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	if !got[0].ForcePush {
		t.Errorf("ForcePush = false, want true")
	}
	if got[0].BeforeSHA != "old111" {
		t.Errorf("BeforeSHA = %q, want old111", got[0].BeforeSHA)
	}
	if got[0].CommitSHA != "new222" {
		t.Errorf("CommitSHA = %q, want new222", got[0].CommitSHA)
	}
	if atomic.LoadUint64(&p.Metrics.ForcePushesReceived) != 1 {
		t.Errorf("ForcePushesReceived = %d, want 1", p.Metrics.ForcePushesReceived)
	}
}

func TestForcePushDisabledFallsBackToHead(t *testing.T) {
	p := New("", "/webhook", "")
	p.cfg.DetectForcePush = false
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{
		"before":"old111","after":"new222","forced":true,
		"repository":{"full_name":"acme/widgets"},
		"pusher":{"name":"dev"}
	}`)
	resp := post(t, url, "push", "", body)
	resp.Body.Close()

	got := drain(t, events, 1)
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	if got[0].ForcePush {
		t.Errorf("ForcePush = true, want false (detection disabled)")
	}
	if got[0].CommitSHA != "new222" {
		t.Errorf("sha = %q, want new222", got[0].CommitSHA)
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	p := New("", "/webhook", testSecret)
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{"after":"bbb","repository":{"full_name":"acme/widgets"},"commits":[{"id":"c1"}]}`)
	// Sign with the WRONG secret.
	resp := post(t, url, "push", sign("wrong-key", body), body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	assertNoEvent(t, events)
	if atomic.LoadUint64(&p.Metrics.SignaturesRejected) != 1 {
		t.Errorf("SignaturesRejected = %d, want 1", p.Metrics.SignaturesRejected)
	}
	if atomic.LoadUint64(&p.Metrics.CommitsEmitted) != 0 {
		t.Errorf("CommitsEmitted = %d, want 0", p.Metrics.CommitsEmitted)
	}
}

func TestMissingSignatureRejectedWhenSecretSet(t *testing.T) {
	p := New("", "/webhook", testSecret)
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{"after":"bbb","repository":{"full_name":"acme/widgets"},"commits":[{"id":"c1"}]}`)
	resp := post(t, url, "push", "", body) // no signature header
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	assertNoEvent(t, events)
}

func TestPingAcknowledgedNoEvents(t *testing.T) {
	p := New("", "/webhook", testSecret)
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{"zen":"Keep it logically awesome.","hook_id":1}`)
	resp := post(t, url, "ping", sign(testSecret, body), body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ping status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	assertNoEvent(t, events)
	if atomic.LoadUint64(&p.Metrics.PushEventsReceived) != 0 {
		t.Errorf("PushEventsReceived = %d, want 0 for a ping", p.Metrics.PushEventsReceived)
	}
}

func TestUnknownEventIgnored(t *testing.T) {
	p := New("", "/webhook", testSecret)
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(`{"action":"opened"}`)
	resp := post(t, url, "issues", sign(testSecret, body), body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (acknowledged+ignored)", resp.StatusCode)
	}
	resp.Body.Close()
	assertNoEvent(t, events)
}

func TestGetMethodRejected(t *testing.T) {
	p := New("", "/webhook", "")
	url, _, _, cancel := startProvider(t, p)
	defer cancel()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestBranchDeletionEmitsNothing(t *testing.T) {
	p := New("", "/webhook", "")
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	body := []byte(fmt.Sprintf(`{
		"before":"old111","after":"%s","deleted":true,
		"repository":{"full_name":"acme/widgets"}
	}`, zeroSHA))
	resp := post(t, url, "push", "", body)
	resp.Body.Close()
	assertNoEvent(t, events)
}

func TestOwnerFallbackFromOwnerLogin(t *testing.T) {
	p := New("", "/webhook", "")
	url, events, _, cancel := startProvider(t, p)
	defer cancel()

	// No full_name — must fall back to repository.owner.login + repository.name.
	body := []byte(`{
		"after":"bbb",
		"repository":{"name":"widgets","owner":{"login":"acme"}},
		"commits":[{"id":"c1"}]
	}`)
	resp := post(t, url, "push", "", body)
	resp.Body.Close()

	got := drain(t, events, 1)
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	if got[0].RepoOwner != "acme" || got[0].RepoName != "widgets" {
		t.Errorf("repo = %s/%s, want acme/widgets", got[0].RepoOwner, got[0].RepoName)
	}
}

func TestContextCancelShutsDownServer(t *testing.T) {
	p := New("", "/webhook", "")
	url, events, errs, cancel := startProvider(t, p)

	cancel()
	// The events channel must close after shutdown.
	select {
	case _, ok := <-events:
		if ok {
			// Could be a buffered event; keep draining until closed.
			for range events {
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("events channel not closed within 3s of context cancel")
	}
	// No error should have been surfaced for a clean shutdown.
	select {
	case err := <-errs:
		if err != nil {
			t.Errorf("clean shutdown surfaced error: %v", err)
		}
	default:
	}
	// Server should no longer accept connections.
	if _, err := http.Get(url); err == nil {
		t.Errorf("server still serving after shutdown")
	}
}

func TestBindFailureSurfacesError(t *testing.T) {
	// Occupy a port, then point the provider at it to force a bind failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	p := New(addr, "/webhook", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, errs := p.Stream(ctx)

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("expected a bind error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no bind error surfaced within 3s")
	}
}

func TestValidSignatureRejectsMalformedHeaders(t *testing.T) {
	body := []byte("payload")
	good := sign(testSecret, body)
	cases := []struct {
		name string
		hdr  string
		want bool
	}{
		{"valid", good, true},
		{"missing prefix", good[len("sha256="):], false},
		{"empty", "", false},
		{"bad hex", "sha256=zzzz", false},
		{"wrong length", "sha256=abcd", false},
		{"sha1 prefix", "sha1=" + good[len("sha256="):], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSignature(testSecret, tc.hdr, body); got != tc.want {
				t.Errorf("validSignature(%q) = %v, want %v", tc.hdr, got, tc.want)
			}
		})
	}
}

// drain collects up to n events from ch (with a per-test timeout).
func drain(t *testing.T, ch <-chan ingestion.CommitEvent, n int) []ingestion.CommitEvent {
	t.Helper()
	var got []ingestion.CommitEvent
	timeout := time.After(2 * time.Second)
	for len(got) < n {
		select {
		case e, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, e)
		case <-timeout:
			return got
		}
	}
	return got
}

// assertNoEvent fails if any event arrives within a short window.
func assertNoEvent(t *testing.T, ch <-chan ingestion.CommitEvent) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected event emitted: %+v", e)
	case <-time.After(200 * time.Millisecond):
	}
}

// Ensure the provider satisfies the interface at compile time.
var _ ingestion.Provider = (*Provider)(nil)

// silence unused import if io is only used transitively in some build configs.
var _ = io.Discard
