package fetch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
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
