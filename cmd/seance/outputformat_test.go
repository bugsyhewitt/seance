package main

import (
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output/ndjson"
	outtext "github.com/bugsyhewitt/seance/internal/output/text"
	"github.com/bugsyhewitt/seance/pkg/config"
)

// TestStreamFormat_ValidAndDefault verifies --output normalization: empty and
// "json" (any case, surrounding space) map to NDJSON; "text" maps to the text
// stream. This is the validation that makes the previously-dead OutputFormat flag
// real.
func TestStreamFormat_ValidAndDefault(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", formatJSON},
		{"json", formatJSON},
		{"JSON", formatJSON},
		{"  json  ", formatJSON},
		{"text", formatText},
		{"TEXT", formatText},
		{" text ", formatText},
	}
	for _, c := range cases {
		got, err := streamFormat(c.in)
		if err != nil {
			t.Errorf("streamFormat(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("streamFormat(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStreamFormat_SarifRejectedWithHint verifies the SARIF document format is
// rejected for the stdout stream and the operator is pointed at --sarif-file
// rather than being silently ignored.
func TestStreamFormat_SarifRejectedWithHint(t *testing.T) {
	_, err := streamFormat("sarif")
	if err == nil {
		t.Fatal("expected --output sarif to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "--sarif-file") {
		t.Errorf("error should point to --sarif-file, got %q", err.Error())
	}
}

// TestStreamFormat_UnknownRejected verifies a typo'd format fails loudly instead
// of being silently ignored (the old --output behavior).
func TestStreamFormat_UnknownRejected(t *testing.T) {
	_, err := streamFormat("yaml")
	if err == nil {
		t.Fatal("expected unknown format to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("error should name the bad value, got %q", err.Error())
	}
}

// TestPrimaryStdoutSink_SelectsByFormat verifies the primary stdout sink honors
// OutputFormat when --tui is off: "json" yields the NDJSON sink, "text" yields the
// text sink. (--tui-on-a-TTY selection is environment-dependent and covered by
// the existing TUI tests; here we assert the format-driven branch.)
func TestPrimaryStdoutSink_SelectsByFormat(t *testing.T) {
	jsonSink := primaryStdoutSink(config.Config{OutputFormat: "json"})
	if _, ok := jsonSink.(*ndjson.Sink); !ok {
		t.Errorf("OutputFormat=json should select the NDJSON sink, got %T", jsonSink)
	}

	textSink := primaryStdoutSink(config.Config{OutputFormat: "text"})
	if _, ok := textSink.(*outtext.Sink); !ok {
		t.Errorf("OutputFormat=text should select the text sink, got %T", textSink)
	}

	// Empty defaults to NDJSON (the historical behavior).
	defSink := primaryStdoutSink(config.Config{})
	if _, ok := defSink.(*ndjson.Sink); !ok {
		t.Errorf("empty OutputFormat should default to the NDJSON sink, got %T", defSink)
	}
}
