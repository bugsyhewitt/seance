package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
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
