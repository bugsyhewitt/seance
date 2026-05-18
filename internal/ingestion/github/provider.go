// Package github implements the GitHub public events API provider for séance.
// It polls GET /events at the interval specified by X-Poll-Interval, caches
// ETags for conditional requests, and emits CommitEvents for PushEvents only.
//
// Rate-limit budget (single token, authenticated):
//   - 60 polls/hour @ 60s interval  =    60 requests
//   - ~900 surviving commits/hour   =   900 fetches  (post-prefilter)
//   - Total                         =   960 req/hr   (~19% of 5,000 ceiling)
//
// This provider does NOT fetch file content — that is the Fetcher's job.
// Pre-filtering happens downstream in the prefilter package.
package github

import (
	"context"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

const (
	defaultPollInterval = 60 // seconds; overridden by X-Poll-Interval header
	eventsEndpoint      = "https://api.github.com/events"
	userAgent           = "seance/0.1 (+https://github.com/bugsyhewitt/seance)"
)

// Provider polls the GitHub public events API and emits PushEvent commits.
type Provider struct {
	token        string
	pollInterval int // seconds
}

// New returns a GitHub provider. token may be empty for unauthenticated
// access (rate limit: 60 req/hr — not viable for production use).
func New(token string) *Provider {
	return &Provider{
		token:        token,
		pollInterval: defaultPollInterval,
	}
}

// Name implements ingestion.Provider.
func (p *Provider) Name() string { return "github" }

// Stream implements ingestion.Provider. Real implementation in v0.1.
// Stub: exits immediately when ctx is cancelled.
func (p *Provider) Stream(ctx context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
	events := make(chan ingestion.CommitEvent)
	errs := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errs)
		<-ctx.Done()
	}()
	return events, errs
}
