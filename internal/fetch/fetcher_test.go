package fetch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/throttle"
)

func TestGitHubFetcher_FetchCompare_RecoversOrphanedDiff(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/compare_forcepush.json")
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer srv.Close()

	f := fetch.NewGitHubFetcher("", srv.URL)
	event := ingestion.CommitEvent{
		RepoOwner: "erin", RepoName: "leaky-service",
		CommitSHA: "1111111111111111111111111111111111111111",
		BeforeSHA: "2222222222222222222222222222222222222222",
		ForcePush: true,
	}

	results, err := f.FetchCompare(context.Background(), event)
	if err != nil {
		t.Fatalf("FetchCompare: %v", err)
	}

	// The compare endpoint must be called with head...before so the diff carries
	// the commits orphaned by the rewrite.
	wantPath := "/repos/erin/leaky-service/compare/1111111111111111111111111111111111111111...2222222222222222222222222222222222222222"
	if gotPath != wantPath {
		t.Errorf("compare path = %q, want %q", gotPath, wantPath)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 file, got %d", len(results))
	}
	if results[0].Skipped {
		t.Fatalf("orphaned file should not be skipped: %s", results[0].SkipReason)
	}
	if results[0].FileRef.Path != "config/prod.env" {
		t.Errorf("unexpected path: %s", results[0].FileRef.Path)
	}
	if len(results[0].Lines) == 0 {
		t.Error("expected non-empty patch lines from the orphaned commit")
	}
}

func TestGitHubFetcher_FetchCompare_NoBeforeSHA(t *testing.T) {
	f := fetch.NewGitHubFetcher("", "http://invalid.invalid")
	results, err := f.FetchCompare(context.Background(), ingestion.CommitEvent{CommitSHA: "abc"})
	if err != nil {
		t.Fatalf("FetchCompare with empty BeforeSHA should be a no-op, got: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results when BeforeSHA is empty, got %d", len(results))
	}
}

// TestGitHubFetcher_SetHTTPClient_InstallsRateLimiter verifies the --rate-limit
// integration point on the fetcher: a wrapped client installed via
// SetHTTPClient must actually be consulted on every outbound request, throttling
// burst traffic above the configured rate. This is the contract pipeline.go
// relies on when it shares one limiter across the fetcher and providers.
func TestGitHubFetcher_SetHTTPClient_InstallsRateLimiter(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/commit_abc123.json")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer srv.Close()

	l := throttle.New(20, 1) // 20 req/s, burst 1 ⇒ ~50ms wait between requests
	f := fetch.NewGitHubFetcher("", srv.URL)
	f.SetHTTPClient(throttle.Wrap(l, nil))

	event := ingestion.CommitEvent{
		RepoOwner: "alice", RepoName: "my-project",
		CommitSHA: "abc123def456abc123def456abc123def456abc1",
	}
	ref := ingestion.FileRef{Path: ".env", Status: "added"}

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := f.Fetch(context.Background(), event, ref); err != nil {
			t.Fatalf("Fetch #%d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("hits=%d, want 3", hits)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("3 fetches at 20 req/s (burst 1) took only %v, expected the limiter to delay them", elapsed)
	}
	if got := atomic.LoadUint64(&l.ThrottledRequests); got < 2 {
		t.Errorf("ThrottledRequests=%d, want >= 2 (2 of 3 requests should have waited)", got)
	}
}

// TestGitHubFetcher_SetHTTPClient_NilIsIgnored verifies the defensive no-op:
// SetHTTPClient(nil) keeps the original client rather than nil-ing it out,
// which would crash the fetcher on the next request.
func TestGitHubFetcher_SetHTTPClient_NilIsIgnored(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/commit_abc123.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer srv.Close()

	f := fetch.NewGitHubFetcher("", srv.URL)
	f.SetHTTPClient(nil) // must not crash subsequent requests

	event := ingestion.CommitEvent{
		RepoOwner: "alice", RepoName: "my-project",
		CommitSHA: "abc123def456abc123def456abc123def456abc1",
	}
	ref := ingestion.FileRef{Path: ".env", Status: "added"}
	if _, err := f.Fetch(context.Background(), event, ref); err != nil {
		t.Fatalf("Fetch after SetHTTPClient(nil): %v", err)
	}
}

func TestGitHubFetcher_ReturnsContent(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/commit_abc123.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer srv.Close()

	f := fetch.NewGitHubFetcher("", srv.URL)
	event := ingestion.CommitEvent{
		RepoOwner: "alice", RepoName: "my-project",
		CommitSHA: "abc123def456abc123def456abc123def456abc1",
	}
	ref := ingestion.FileRef{Path: ".env", Status: "added"}

	fc, err := f.Fetch(context.Background(), event, ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fc.Skipped {
		t.Fatalf("file should not be skipped, reason: %s", fc.SkipReason)
	}
	if len(fc.Lines) == 0 {
		t.Error("expected non-empty lines")
	}
}
