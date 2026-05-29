package text

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
)

func sampleFinding() output.Finding {
	return output.Finding{
		RuleID:      "aws-access-key",
		RuleDesc:    "AWS access key",
		Provider:    "events",
		RepoOwner:   "alice",
		RepoName:    "repo",
		CommitSHA:   "deadbeefcafe",
		FilePath:    ".env",
		LineNumber:  12,
		Redacted:    "AKIA****WXYZ",
		Confidence:  0.90,
		Tags:        []string{"aws"},
		Timestamp:   time.Unix(1700000000, 0),
		Fingerprint: "abcd1234",
	}
}

func TestEmit_LineShape(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf)
	if err := s.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("emit: %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("line must be newline-terminated: %q", out)
	}
	// Exactly one line.
	if got := strings.Count(out, "\n"); got != 1 {
		t.Fatalf("expected exactly one line, got %d: %q", got, out)
	}

	for _, want := range []string{
		"[HIGH]",
		"rule=aws-access-key",
		"repo=alice/repo",
		"file=.env:12",
		"conf=0.90",
		"redacted=AKIA****WXYZ",
		"fp=abcd1234",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("line missing %q: %q", want, out)
		}
	}
}

func TestEmit_NeverLeaksRawSecret(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf)
	f := sampleFinding()
	// There is no raw field on Finding; assert a plausible raw value can never
	// appear because only redacted/locator fields are written.
	if err := s.Emit(context.Background(), f); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if strings.Contains(buf.String(), "AKIA2E4F6H8J0L2N4P6R") {
		t.Error("text output must never contain a raw secret value")
	}
}

func TestEmit_ConfidenceBuckets(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0.95, "[HIGH]"},
		{0.90, "[HIGH]"},
		{0.80, "[MED] "},
		{0.70, "[MED] "},
		{0.69, "[LOW] "},
		{0.0, "[LOW] "},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		f := sampleFinding()
		f.Confidence = c.conf
		if err := New(&buf).Emit(context.Background(), f); err != nil {
			t.Fatalf("emit: %v", err)
		}
		if !strings.HasPrefix(buf.String(), c.want) {
			t.Errorf("conf %.2f: want prefix %q, got %q", c.conf, c.want, buf.String())
		}
	}
}

func TestEmit_EmptyFieldsPlaceholdered(t *testing.T) {
	var buf bytes.Buffer
	// Zero-value finding: every string field empty, no line number, no fingerprint.
	if err := New(&buf).Emit(context.Background(), output.Finding{}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"rule=-", "repo=-/-", "file=-", "redacted=-"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty-field placeholder missing %q: %q", want, out)
		}
	}
	// No fingerprint field when Fingerprint is empty.
	if strings.Contains(out, "fp=") {
		t.Errorf("empty fingerprint must be omitted, got %q", out)
	}
	// No line suffix when LineNumber is 0.
	if strings.Contains(out, "file=-:") {
		t.Errorf("zero line number must omit the :N suffix, got %q", out)
	}
}

func TestEmit_MultipleFindingsOneLineEach(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf)
	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if got := strings.Count(buf.String(), "\n"); got != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", got, buf.String())
	}
}

func TestClose_NoOp(t *testing.T) {
	if err := New(&bytes.Buffer{}).Close(); err != nil {
		t.Errorf("Close should be a no-op, got %v", err)
	}
}
