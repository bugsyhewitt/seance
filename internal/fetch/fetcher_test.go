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
