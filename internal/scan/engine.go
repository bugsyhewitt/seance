// Package scan runs the signature engine over fetched file content.
// Real implementation in v0.1; this file defines the Engine type and interface.
package scan

import (
	"context"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// Engine runs detection rules and entropy analysis over fetched file content.
type Engine struct {
	rules []ruleset.Rule
	sinks []output.Sink
}

// New constructs an Engine with the given rules and output sinks.
func New(rules []ruleset.Rule, sinks ...output.Sink) *Engine {
	return &Engine{rules: rules, sinks: sinks}
}

// Scan runs all rules against content and emits Findings to all sinks.
// Returns the number of findings emitted. Stub: real implementation in v0.1.
func (e *Engine) Scan(ctx context.Context, content fetch.FileContent) (int, error) {
	if content.Skipped {
		return 0, nil
	}
	// TODO(v0.1): iterate rules, compile regexes, check keywords, run entropy
	return 0, nil
}
