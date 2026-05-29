package search_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	searchprovider "github.com/bugsyhewitt/seance/internal/ingestion/search"
)

// TestProvider_ParsesSearchResults verifies that the provider issues a
// search request carrying the keyword, parses commit results into CommitEvents
// with FilesKnown=false, and skips malformed (empty-SHA) results.
func TestProvider_ParsesSearchResults(t *testing.T) {
	fixture, err := os.ReadFile("testdata/search_commits.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		w.Header().Set("X-RateLimit-Remaining", "29")
		w.Header().Set("X-RateLimit-Reset", "9999999999")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	events, errs := p.Stream(ctx)
	var got []struct {
		sha        string
		owner      string
		name       string
		provider   string
		filesKnown bool
	}
	for e := range events {
		got = append(got, struct {
			sha        string
			owner      string
			name       string
			provider   string
			filesKnown bool
		}{e.CommitSHA, e.RepoOwner, e.RepoName, e.Provider, e.FilesKnown})
	}
	if err := <-errs; err != nil && err.Error() != "context deadline exceeded" {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotQuery != "acme-corp" {
		t.Errorf("search query = %q, want %q", gotQuery, "acme-corp")
	}

	// Two valid results; the empty-SHA result is skipped.
	if len(got) != 2 {
		t.Fatalf("expected 2 commit events (third is malformed), got %d", len(got))
	}
	if got[0].sha != "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111" {
		t.Errorf("event 0 SHA = %q", got[0].sha)
	}
	if got[0].owner != "acme-corp" || got[0].name != "infra" {
		t.Errorf("event 0 repo = %s/%s, want acme-corp/infra", got[0].owner, got[0].name)
	}
	if got[0].provider != "search" {
		t.Errorf("event 0 provider = %q, want search", got[0].provider)
	}
	if got[0].filesKnown {
		t.Error("search events must have FilesKnown=false (fetcher discovers files)")
	}
	if got[1].sha != "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222" {
		t.Errorf("event 1 SHA = %q", got[1].sha)
	}
}

// TestProvider_NoKeywords verifies the provider is inert (emits nothing, errors
// nothing, makes no HTTP calls) when configured with no keywords.
func TestProvider_NoKeywords(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(200)
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	events, errs := p.Stream(ctx)
	var count int
	for range events {
		count++
	}
	if err := <-errs; err != nil {
		t.Fatalf("inert provider must not error, got %v", err)
	}
	if count != 0 {
		t.Errorf("inert provider emitted %d events, want 0", count)
	}
	if c := atomic.LoadInt32(&calls); c != 0 {
		t.Errorf("inert provider made %d HTTP calls, want 0", c)
	}
}

// TestProvider_KeywordCleaning verifies blank/whitespace keywords are dropped.
func TestProvider_KeywordCleaning(t *testing.T) {
	p := searchprovider.New("", "  acme-corp ", "", "   ", "internal.example.com")
	kw := p.Keywords()
	if len(kw) != 2 {
		t.Fatalf("expected 2 cleaned keywords, got %d: %v", len(kw), kw)
	}
	if kw[0] != "acme-corp" || kw[1] != "internal.example.com" {
		t.Errorf("cleaned keywords = %v", kw)
	}
}

// TestProvider_DedupsWithinRun verifies the same commit SHA returned on
// successive polls is emitted only once (the Search index returns stable top
// results, so without intra-run dedup the channel would be spammed).
func TestProvider_DedupsWithinRun(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/search_commits.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "29")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture) // identical results every poll
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
	p.PollInterval = 20 * time.Millisecond // poll several times in the window

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	events, _ := p.Stream(ctx)
	var count int
	for range events {
		count++
	}

	// Despite multiple polls, each unique commit is emitted exactly once.
	if count != 2 {
		t.Errorf("expected 2 events across many polls (dedup), got %d", count)
	}
	if reqs := atomic.LoadUint64(&p.Metrics.SearchRequests); reqs < 2 {
		t.Errorf("expected multiple polls, got %d search requests", reqs)
	}
}

// TestProvider_AdaptiveCadence_BackoffAndRecovery verifies the search-budget
// governor backs off when X-RateLimit-Remaining is at/below the floor and
// recovers (two-way, not one-way) once the budget is healthy again.
func TestProvider_AdaptiveCadence_BackoffAndRecovery(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/search_commits.json")

	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&n, 1)
		w.Header().Set("Content-Type", "application/json")
		if c == 1 {
			w.Header().Set("X-RateLimit-Remaining", "1") // <= floor → backoff
		} else {
			w.Header().Set("X-RateLimit-Remaining", "25") // healthy → recover
		}
		w.Header().Set("X-RateLimit-Reset", "9999999999")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
	p.PollInterval = 20 * time.Millisecond
	p.LowBudgetInterval = 30 * time.Millisecond // short so the test is fast

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	events, _ := p.Stream(ctx)
	for range events {
	} // drain

	calls := atomic.LoadInt32(&n)
	if calls < 2 {
		t.Fatalf("expected at least 2 polls (backoff + recovery), got %d", calls)
	}
	if remaining := atomic.LoadInt64(&p.Metrics.RateLimitRemaining); remaining < 20 {
		t.Errorf("expected healthy remaining after recovery, got %d", remaining)
	}
}

// TestProvider_DateRange_QueryQualifier verifies that a configured committer-date
// window is rendered into the GitHub Search query as a committer-date: qualifier
// appended to the keyword, for each of the three window shapes.
func TestProvider_DateRange_QueryQualifier(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/search_commits.json")

	cases := []struct {
		name      string
		since     string
		until     string
		wantQuery string
	}{
		{"both bounds", "2026-01-01", "2026-03-01", "acme-corp committer-date:2026-01-01..2026-03-01"},
		{"since only", "2026-01-01", "", "acme-corp committer-date:>=2026-01-01"},
		{"until only", "", "2026-03-01", "acme-corp committer-date:<=2026-03-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotQuery string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.Query().Get("q")
				w.Header().Set("X-RateLimit-Remaining", "29")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write(fixture)
			}))
			defer srv.Close()

			p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
			if err := p.SetDateRange(tc.since, tc.until); err != nil {
				t.Fatalf("SetDateRange(%q,%q): %v", tc.since, tc.until, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			events, _ := p.Stream(ctx)
			for range events {
			} // drain

			if gotQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, tc.wantQuery)
			}
		})
	}
}

// TestProvider_DateRange_Unset verifies that with no window configured the query
// is the bare keyword (no committer-date qualifier) — the prior behavior is
// byte-for-byte unchanged.
func TestProvider_DateRange_Unset(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/search_commits.json")

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		w.Header().Set("X-RateLimit-Remaining", "29")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(fixture)
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
	// SetDateRange not called at all → no qualifier.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	events, _ := p.Stream(ctx)
	for range events {
	}

	if gotQuery != "acme-corp" {
		t.Errorf("query = %q, want bare keyword %q", gotQuery, "acme-corp")
	}
}

// TestProvider_DateRange_EmptyIsNoOp verifies SetDateRange with both bounds blank
// (or whitespace) succeeds and leaves the query unscoped.
func TestProvider_DateRange_EmptyIsNoOp(t *testing.T) {
	p := searchprovider.New("", "acme-corp")
	if err := p.SetDateRange("  ", ""); err != nil {
		t.Fatalf("empty range should be a no-op, got %v", err)
	}
}

// TestProvider_DateRange_Validation verifies bad dates and inverted ranges are
// rejected so a typo'd flag fails loudly instead of returning an unscoped stream.
func TestProvider_DateRange_Validation(t *testing.T) {
	cases := []struct {
		name  string
		since string
		until string
	}{
		{"bad since", "2026-13-99", ""},
		{"bad until", "", "not-a-date"},
		{"non-iso since", "01/01/2026", ""},
		{"inverted range", "2026-03-01", "2026-01-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := searchprovider.New("", "acme-corp")
			if err := p.SetDateRange(tc.since, tc.until); err == nil {
				t.Errorf("SetDateRange(%q,%q) = nil, want error", tc.since, tc.until)
			}
		})
	}
}

// TestProvider_DateRange_EqualBoundsAllowed verifies a single-day window
// (since == until) is accepted.
func TestProvider_DateRange_EqualBoundsAllowed(t *testing.T) {
	p := searchprovider.New("", "acme-corp")
	if err := p.SetDateRange("2026-02-15", "2026-02-15"); err != nil {
		t.Fatalf("single-day window should be valid, got %v", err)
	}
}

// TestProvider_SurfacesHTTPError verifies a non-200 response is surfaced on the
// error channel (e.g. a 403 secondary-rate-limit signal).
func TestProvider_SurfacesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"rate limited"}`))
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	events, errs := p.Stream(ctx)
	for range events {
	}
	err := <-errs
	if err == nil {
		t.Fatal("expected an error for a 403 response, got nil")
	}
}

// TestProvider_SetPollInterval_Override verifies that a positive interval above
// the floor is applied verbatim to the provider's normal cadence and returned as
// the effective value.
func TestProvider_SetPollInterval_Override(t *testing.T) {
	p := searchprovider.New("", "acme-corp")
	want := 30 * time.Second
	got := p.SetPollInterval(want)
	if got != want {
		t.Fatalf("SetPollInterval(%s) returned %s, want %s", want, got, want)
	}
	if p.PollInterval != want {
		t.Fatalf("PollInterval = %s, want %s", p.PollInterval, want)
	}
}

// TestProvider_SetPollInterval_ClampsBelowFloor verifies that a too-eager
// interval is clamped up to the 10s floor (protecting the Search-API quota)
// rather than honored, and that the clamped value is returned.
func TestProvider_SetPollInterval_ClampsBelowFloor(t *testing.T) {
	p := searchprovider.New("", "acme-corp")
	got := p.SetPollInterval(2 * time.Second)
	want := 10 * time.Second
	if got != want {
		t.Fatalf("SetPollInterval(2s) returned %s, want clamp to %s", got, want)
	}
	if p.PollInterval != want {
		t.Fatalf("PollInterval = %s, want clamped %s", p.PollInterval, want)
	}
}

// TestProvider_SetPollInterval_ZeroIsNoOp verifies that a zero or negative
// interval leaves the provider's existing (default) cadence untouched, so an
// unset --watch-interval changes nothing.
func TestProvider_SetPollInterval_ZeroIsNoOp(t *testing.T) {
	p := searchprovider.New("", "acme-corp")
	before := p.PollInterval
	if got := p.SetPollInterval(0); got != before {
		t.Fatalf("SetPollInterval(0) returned %s, want unchanged %s", got, before)
	}
	if p.PollInterval != before {
		t.Fatalf("PollInterval = %s after no-op, want %s", p.PollInterval, before)
	}
	if got := p.SetPollInterval(-5 * time.Second); got != before {
		t.Fatalf("SetPollInterval(-5s) returned %s, want unchanged %s", got, before)
	}
	if p.PollInterval != before {
		t.Fatalf("PollInterval = %s after negative no-op, want %s", p.PollInterval, before)
	}
}

// TestProvider_SetPollInterval_GovernsCadence verifies the override actually
// drives how often the provider polls: with a short interval it sweeps the
// keyword list multiple times inside a fixed window.
func TestProvider_SetPollInterval_GovernsCadence(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	p := searchprovider.NewWithBaseURL("", srv.URL, "acme-corp")
	// Exercise the override path with a value above the 10s floor so it is
	// honored verbatim, proving SetPollInterval drives p.PollInterval...
	if got := p.SetPollInterval(15 * time.Second); got != 15*time.Second {
		t.Fatalf("SetPollInterval(15s) = %s, want 15s", got)
	}
	// ...then assign the field directly to keep the actual loop fast for the test.
	p.PollInterval = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	events, errs := p.Stream(ctx)
	go func() {
		for range events {
		}
	}()
	for range errs {
	}
	if n := atomic.LoadInt64(&hits); n < 2 {
		t.Fatalf("expected multiple polls in the window, got %d", n)
	}
}
