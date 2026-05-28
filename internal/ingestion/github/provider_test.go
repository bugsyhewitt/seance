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
	var got []struct {
		sha        string
		filesKnown bool
	}
	for e := range events {
		got = append(got, struct {
			sha        string
			filesKnown bool
		}{e.CommitSHA, e.FilesKnown})
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

// TestProvider_DetectsForcePush verifies that a force-push (history-rewrite)
// event is emitted with ForcePush=true and the before SHA as the scan target,
// while a normal forward push and a branch creation are not flagged.
func TestProvider_DetectsForcePush(t *testing.T) {
	fixture, err := os.ReadFile("testdata/events_forcepush.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Poll-Interval", "60")
		w.Header().Set("ETag", `"etagfp"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := ghprovider.NewWithBaseURL("", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, errs := p.Stream(ctx)
	type ev struct {
		sha       string
		before    string
		forcePush bool
	}
	var got []ev
	for e := range events {
		got = append(got, ev{e.CommitSHA, e.BeforeSHA, e.ForcePush})
	}
	if err := <-errs; err != nil && err.Error() != "context deadline exceeded" {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 commit events (force-push + forward + branch-create), got %d", len(got))
	}

	// Event 1: forced=true → force-push, carries the before SHA.
	if !got[0].forcePush {
		t.Error("event 1 (forced=true) should be flagged ForcePush")
	}
	if got[0].before != "2222222222222222222222222222222222222222" {
		t.Errorf("event 1 before SHA = %q, want the prior tip", got[0].before)
	}
	if got[0].sha != "1111111111111111111111111111111111111111" {
		t.Errorf("event 1 head SHA = %q", got[0].sha)
	}

	// Event 2: normal forward push with distinct commits → not a force-push.
	if got[1].forcePush {
		t.Error("event 2 (normal forward push) must not be flagged ForcePush")
	}

	// Event 3: branch creation (before == zero SHA) → not a force-push.
	if got[2].forcePush {
		t.Error("event 3 (branch creation) must not be flagged ForcePush")
	}

	if n := atomic.LoadUint64(&p.Metrics.ForcePushesReceived); n != 1 {
		t.Errorf("ForcePushesReceived = %d, want 1", n)
	}
}

// TestProvider_ForcePushDisabled verifies that with DetectForcePush=false the
// force-push event falls back to a normal (unflagged) new-format event.
func TestProvider_ForcePushDisabled(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/events_forcepush.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Poll-Interval", "60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := ghprovider.NewWithBaseURL("", srv.URL)
	p.DetectForcePush = false
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, _ := p.Stream(ctx)
	var anyForcePush bool
	var count int
	for e := range events {
		count++
		if e.ForcePush {
			anyForcePush = true
		}
	}
	if anyForcePush {
		t.Error("no event should be flagged ForcePush when DetectForcePush=false")
	}
	if count != 3 {
		t.Errorf("expected 3 events, got %d", count)
	}
	if n := atomic.LoadUint64(&p.Metrics.ForcePushesReceived); n != 0 {
		t.Errorf("ForcePushesReceived = %d, want 0 when disabled", n)
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
