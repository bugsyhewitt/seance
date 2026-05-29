package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
)

// TestParseFormat covers normalization, the empty-string default, and rejection
// of unknown values so a typo fails loudly at startup.
func TestParseFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"", FormatJSON, false},
		{"json", FormatJSON, false},
		{"JSON", FormatJSON, false},
		{"  slack  ", FormatSlack, false},
		{"Slack", FormatSlack, false},
		{"discord", FormatDiscord, false},
		{"DISCORD", FormatDiscord, false},
		{"telegram", "", true},
		{"xml", "", true},
	}
	for _, c := range cases {
		got, err := ParseFormat(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// captureBody starts a test server that records the body of a single POST and
// returns the recorded bytes after the sink has delivered the finding.
func captureBody(t *testing.T, cfg Config, f output.Finding) []byte {
	t.Helper()
	var got []byte
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		got = buf.Bytes()
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	cfg.URL = srv.URL
	s := New(cfg)
	if err := s.Emit(context.Background(), f); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	<-done
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return got
}

// TestSlackFormatBody verifies the Slack envelope shape and that the redacted
// summary carries the locator fields a responder needs.
func TestSlackFormatBody(t *testing.T) {
	body := captureBody(t, Config{Format: FormatSlack}, sampleFinding())

	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("Slack body is not valid JSON: %v (%s)", err, body)
	}
	text, ok := env["text"].(string)
	if !ok {
		t.Fatalf("Slack body missing string \"text\" field: %s", body)
	}
	if _, hasContent := env["content"]; hasContent {
		t.Errorf("Slack body must not carry a Discord \"content\" field: %s", body)
	}
	for _, want := range []string{"AWS access key id", "octocat/hello-world", ".env", "AKIA********************WXYZ", "0.90"} {
		if !strings.Contains(text, want) {
			t.Errorf("Slack text missing %q\ngot: %s", want, text)
		}
	}
}

// TestDiscordFormatBody verifies the Discord envelope shape.
func TestDiscordFormatBody(t *testing.T) {
	body := captureBody(t, Config{Format: FormatDiscord}, sampleFinding())

	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("Discord body is not valid JSON: %v (%s)", err, body)
	}
	content, ok := env["content"].(string)
	if !ok {
		t.Fatalf("Discord body missing string \"content\" field: %s", body)
	}
	if _, hasText := env["text"]; hasText {
		t.Errorf("Discord body must not carry a Slack \"text\" field: %s", body)
	}
	if !strings.Contains(content, "octocat/hello-world") {
		t.Errorf("Discord content missing repo locator\ngot: %s", content)
	}
}

// TestJSONFormatBodyUnchanged confirms the default format still POSTs the raw
// redacted Finding object — backward compatibility for existing endpoints.
func TestJSONFormatBodyUnchanged(t *testing.T) {
	want := sampleFinding()
	for _, cfg := range []Config{{}, {Format: FormatJSON}} {
		body := captureBody(t, cfg, want)
		var got output.Finding
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("JSON body did not decode to a Finding: %v (%s)", err, body)
		}
		if got.RuleID != want.RuleID || got.Redacted != want.Redacted ||
			got.RepoOwner != want.RepoOwner || got.Confidence != want.Confidence {
			t.Errorf("decoded finding = %+v, want %+v", got, want)
		}
	}
}

// TestFormatsNeverLeakRawSecret asserts the never-emit-raw-secrets invariant
// holds for every format: only the redacted mask appears, never raw material.
func TestFormatsNeverLeakRawSecret(t *testing.T) {
	for _, format := range []Format{FormatJSON, FormatSlack, FormatDiscord} {
		body := captureBody(t, Config{Format: format}, sampleFinding())
		if bytes.Contains(body, []byte("AKIAIOSFODNN7EXAMPLE")) {
			t.Errorf("format %q leaked raw secret into body: %s", format, body)
		}
		if !bytes.Contains(body, []byte("AKIA********************WXYZ")) {
			t.Errorf("format %q dropped the redacted value: %s", format, body)
		}
	}
}

// TestFindingMessageHandlesSparseFinding verifies the summary degrades cleanly
// when optional locator fields are absent (no panics, no stray separators).
func TestFindingMessageHandlesSparseFinding(t *testing.T) {
	f := output.Finding{
		RuleID:     "generic-key",
		Redacted:   "sha256:abcd1234",
		Confidence: 0.5,
	}
	msg := findingMessage(f)
	if !strings.Contains(msg, "generic-key") {
		t.Errorf("sparse message missing rule id: %s", msg)
	}
	if !strings.Contains(msg, "sha256:abcd1234") {
		t.Errorf("sparse message missing redacted value: %s", msg)
	}
	if strings.Contains(msg, "file:") || strings.Contains(msg, "repo:") {
		t.Errorf("sparse message emitted empty locator lines: %s", msg)
	}
}
