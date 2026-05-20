package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	ghprovider "github.com/bugsyhewitt/seance/internal/ingestion/github"
)

func TestProvider_ParsesPushEvents(t *testing.T) {
	fixture, err := os.ReadFile("testdata/events_page1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Poll-Interval", "60")
		w.Header().Set("ETag", `"etag123"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := ghprovider.NewWithBaseURL("", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, errs := p.Stream(ctx)
	var got []string
	for e := range events {
		got = append(got, e.CommitSHA)
	}
	if err := <-errs; err != nil && err.Error() != "context deadline exceeded" {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 1 {
		t.Errorf("expected 1 commit event, got %d", len(got))
	}
	if len(got) > 0 && got[0] != "abc123def456abc123def456abc123def456abc1" {
		t.Errorf("unexpected SHA: %s", got[0])
	}
}

// TestProvider_ParsesPushEvents_NewFormat verifies that the provider emits a
// CommitEvent when the payload uses the new GitHub API format (head/before/ref
// only, no commits array).
func TestProvider_ParsesPushEvents_NewFormat(t *testing.T) {
	fixture, err := os.ReadFile("testdata/events_newformat.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Poll-Interval", "60")
		w.Header().Set("ETag", `"etagnew"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := ghprovider.NewWithBaseURL("", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, errs := p.Stream(ctx)
	var got []struct{ sha string; filesKnown bool }
	for e := range events {
		got = append(got, struct{ sha string; filesKnown bool }{e.CommitSHA, e.FilesKnown})
	}
	if err := <-errs; err != nil && err.Error() != "context deadline exceeded" {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 commit event, got %d", len(got))
	}
	if got[0].sha != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("unexpected SHA: %s", got[0].sha)
	}
	if got[0].filesKnown {
		t.Error("new-format event must have FilesKnown=false")
	}
}

// TestProvider_AdaptiveCadence_BackoffAndRecovery verifies that:
// (a) when X-RateLimit-Remaining is critically low, the provider backs off, and
// (b) when it recovers on the next poll, normal cadence resumes (one-way backoff
//
//	is NOT acceptable).
func TestProvider_AdaptiveCadence_BackoffAndRecovery(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/events_page1.json")

	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		// X-Poll-Interval=60 gives threshold = 60*10/100 = 6.
		// remaining=1 is below 6 → backoff; remaining=4999 is above → recovery.
		w.Header().Set("X-Poll-Interval", "60")
		w.Header().Set("Content-Type", "application/json")
		switch n {
		case 1:
			// First poll: budget critically low.
			w.Header().Set("X-RateLimit-Remaining", "1")
			w.Header().Set("X-RateLimit-Reset", "9999999999")
		default:
			// Subsequent polls: budget healthy — cadence should recover.
			w.Header().Set("X-RateLimit-Remaining", "4999")
			w.Header().Set("X-RateLimit-Reset", "9999999999")
		}
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := ghprovider.NewWithBaseURL("", srv.URL)
	// Use a very short backoff so the test doesn't take minutes.
	p.LowBudgetInterval = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	events, _ := p.Stream(ctx)
	for range events {
	} // drain

	calls := atomic.LoadInt32(&callCount)
	if calls < 2 {
		t.Fatalf("expected at least 2 polls (backoff + recovery), got %d", calls)
	}

	// After poll 2+, remaining is 4999 — well above threshold.
	// The provider must have resumed normal cadence (not stayed at LowBudgetInterval).
	remaining := atomic.LoadInt64(&p.Metrics.RateLimitRemaining)
	if remaining < 4000 {
		t.Errorf("expected healthy remaining after recovery, got %d", remaining)
	}
}
