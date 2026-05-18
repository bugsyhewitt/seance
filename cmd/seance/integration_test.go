package main_test

import (
	"context"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/ingestion/fake"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/prefilter"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

func TestEndToEnd_FindsSecretInFakeEvent(t *testing.T) {
	event := ingestion.CommitEvent{
		Provider: "fake", RepoOwner: "alice", RepoName: "repo",
		CommitSHA: "deadbeef", AuthorName: "alice",
		Files: []ingestion.FileRef{{Path: ".env", Status: "added"}},
	}

	provider := fake.New(event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, _ := provider.Stream(ctx)

	rules := []ruleset.Rule{{
		ID: "aws-test", Regex: `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}

	var findings []output.Finding
	sink := &collectSink{out: &findings}
	engine := scan.New(rules, sink)

	for e := range events {
		d := prefilter.Filter(e)
		if !d.Keep {
			continue
		}
		for _, ref := range d.Files {
			fc := fetch.FileContent{
				Event:   e,
				FileRef: ref,
				Patch:   "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
				Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
			}
			engine.Scan(ctx, fc)
		}
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

type collectSink struct{ out *[]output.Finding }

func (c *collectSink) Emit(_ context.Context, f output.Finding) error {
	*c.out = append(*c.out, f)
	return nil
}
func (c *collectSink) Close() error { return nil }
