package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/ingestion/fake"
)

// TestMergeProviders_FansAllEvents verifies that mergeProviders fans the
// CommitEvents from multiple providers (the events-stream analogue + the
// search-stream analogue) into one channel, and that the merged channel closes
// only once every provider's stream has drained — preserving the single-provider
// "channel closed ⇒ shutdown" contract the pipeline relies on.
func TestMergeProviders_FansAllEvents(t *testing.T) {
	a := fake.New(
		ingestion.CommitEvent{Provider: "events", CommitSHA: "aaa"},
		ingestion.CommitEvent{Provider: "events", CommitSHA: "bbb"},
	)
	b := fake.New(
		ingestion.CommitEvent{Provider: "search", CommitSHA: "ccc"},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, errs := mergeProviders(ctx, a, b)

	got := map[string]string{} // sha -> provider
	for e := range events {
		got[e.CommitSHA] = e.Provider
	}
	if err := <-errs; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 merged events, got %d: %v", len(got), got)
	}
	if got["aaa"] != "events" || got["bbb"] != "events" {
		t.Errorf("events-provider commits not fanned correctly: %v", got)
	}
	if got["ccc"] != "search" {
		t.Errorf("search-provider commit not fanned correctly: %v", got)
	}
}

// TestMergeProviders_ForwardsError verifies that an error from any single
// provider is surfaced once on the merged error channel.
func TestMergeProviders_ForwardsError(t *testing.T) {
	healthy := fake.New(ingestion.CommitEvent{Provider: "events", CommitSHA: "aaa"})
	broken := &erroringProvider{err: errors.New("boom")}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, errs := mergeProviders(ctx, healthy, broken)
	for range events {
	}
	err := <-errs
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected forwarded error 'boom', got %v", err)
	}
}

// erroringProvider is a minimal ingestion.Provider that emits a single error.
type erroringProvider struct{ err error }

func (e *erroringProvider) Name() string { return "broken" }
func (e *erroringProvider) Stream(_ context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
	ev := make(chan ingestion.CommitEvent)
	er := make(chan error, 1)
	close(ev)
	er <- e.err
	close(er)
	return ev, er
}
