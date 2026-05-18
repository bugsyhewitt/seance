// Package fake provides a deterministic Provider for testing.
package fake

import (
	"context"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

// Provider emits a fixed set of CommitEvents for testing.
type Provider struct{ events []ingestion.CommitEvent }

func New(events ...ingestion.CommitEvent) *Provider { return &Provider{events: events} }
func (p *Provider) Name() string                    { return "fake" }

func (p *Provider) Stream(ctx context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
	out := make(chan ingestion.CommitEvent, len(p.events))
	errs := make(chan error, 1)
	for _, e := range p.events {
		out <- e
	}
	close(out)
	close(errs)
	return out, errs
}
