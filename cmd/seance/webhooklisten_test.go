package main_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/ingestion/webhookrecv"
)

// TestWebhookListenProviderPing checks that the webhookrecv provider starts its
// HTTP listener and responds 200 OK to a GitHub "ping" — the same code path
// runPipeline exercises when --webhook-listen is set.
func TestWebhookListenProviderPing(t *testing.T) {
	t.Parallel()

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	prov := webhookrecv.New(addr, "", "")
	if prov == nil {
		t.Fatal("webhookrecv.New returned nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	prov.Stream(ctx) // launches the HTTP server goroutine

	// Give the goroutine a moment to bind.
	time.Sleep(30 * time.Millisecond)

	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/webhook", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("X-GitHub-Event", "ping")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("ping request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ping got %d, want 200", resp.StatusCode)
	}
}

// TestWebhookListenNoSecretWarning checks that New with a blank secret does not
// panic — the provider doc says it logs a warning but keeps running.
func TestWebhookListenNoSecretWarning(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	prov := webhookrecv.New(addr, "", "")
	if prov == nil {
		t.Fatal("webhookrecv.New returned nil for empty secret")
	}
	// Just confirm construction succeeds; no panic.
}

// TestWebhookListenWithSecret checks that New with a non-empty secret is
// constructable (HMAC verification is exercised in webhookrecv's own tests).
func TestWebhookListenWithSecret(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	prov := webhookrecv.New(addr, "", "s3cr3t")
	if prov == nil {
		t.Fatal("webhookrecv.New returned nil for non-empty secret")
	}
}
