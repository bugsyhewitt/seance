// Package ndjson implements a newline-delimited JSON sink for séance findings.
// Each finding is emitted as a single JSON object followed by a newline,
// suitable for streaming, log ingestion, and composition with jq.
package ndjson

import (
	"context"
	"encoding/json"
	"io"

	"github.com/bugsyhewitt/seance/internal/output"
)

// Sink writes Findings as newline-delimited JSON (NDJSON).
type Sink struct {
	enc *json.Encoder
}

// New returns an NDJSON sink writing to w.
func New(w io.Writer) *Sink {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Sink{enc: enc}
}

// Emit implements output.Sink. Each call writes one JSON line.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	return s.enc.Encode(finding)
}

// Close implements output.Sink. No-op for a stream writer.
func (s *Sink) Close() error { return nil }
