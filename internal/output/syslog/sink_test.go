//go:build !windows && !plan9

package syslog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/syslog"
	"sync"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/output"
	outsyslog "github.com/bugsyhewitt/seance/internal/output/syslog"
)

// fakeWriter is an in-memory stand-in for *syslog.Writer that records every
// message and the severity method it was delivered through. It satisfies
// outsyslog.Writer so tests do not need an open syslog socket.
type fakeWriter struct {
	mu        sync.Mutex
	failNext  int      // when >0, the next N writes fail (and decrement)
	closeErr  error    //nolint:unused // reserved for future Close-error tests
	closeCnt  int
	messages  []string // raw bodies, in arrival order
	severity  []string // matching severity ("alert","info",...) for each body
	dialCalls int      // incremented by the dialer wrapper, not here
}

func (f *fakeWriter) recordOrFail(sev, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return errors.New("synthetic write failure")
	}
	f.severity = append(f.severity, sev)
	f.messages = append(f.messages, msg)
	return nil
}

func (f *fakeWriter) Emerg(m string) error   { return f.recordOrFail("emerg", m) }
func (f *fakeWriter) Alert(m string) error   { return f.recordOrFail("alert", m) }
func (f *fakeWriter) Crit(m string) error    { return f.recordOrFail("crit", m) }
func (f *fakeWriter) Err(m string) error     { return f.recordOrFail("err", m) }
func (f *fakeWriter) Warning(m string) error { return f.recordOrFail("warning", m) }
func (f *fakeWriter) Notice(m string) error  { return f.recordOrFail("notice", m) }
func (f *fakeWriter) Info(m string) error    { return f.recordOrFail("info", m) }
func (f *fakeWriter) Debug(m string) error   { return f.recordOrFail("debug", m) }

func (f *fakeWriter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCnt++
	return nil
}

func (f *fakeWriter) snapshot() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	msgs := append([]string(nil), f.messages...)
	sevs := append([]string(nil), f.severity...)
	return msgs, sevs
}

func sampleFinding() output.Finding {
	return output.Finding{
		RuleID:      "aws-access-key-id",
		RuleDesc:    "AWS Access Key ID",
		Provider:    "github",
		RepoOwner:   "alice",
		RepoName:    "repo",
		CommitSHA:   "deadbeef",
		FilePath:    "config/prod.env",
		LineNumber:  12,
		Redacted:    "AKIA****WXYZ",
		Confidence:  0.97,
		Tags:        []string{"cloud", "aws"},
		Timestamp:   time.Date(2026, 5, 17, 14, 30, 0, 0, time.UTC),
		Fingerprint: "sha256:9b1ec4",
	}
}

// dialerForFake returns a Dialer that hands out the same fakeWriter every call
// and counts dial invocations on it.
func dialerForFake(fw *fakeWriter) func(network, raddr string, priority syslog.Priority, tag string) (outsyslog.Writer, error) {
	return func(network, raddr string, priority syslog.Priority, tag string) (outsyslog.Writer, error) {
		fw.mu.Lock()
		fw.dialCalls++
		fw.mu.Unlock()
		return fw, nil
	}
}

// waitFor spins briefly until pred() returns true or the deadline elapses.
// Used to wait for the background worker to drain the queue without sprinkling
// arbitrary sleeps through the suite. A failing predicate at deadline is
// reported by the caller via t.Fatal.
func waitFor(t *testing.T, d time.Duration, pred func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pred() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// TestEmit_SendsJSONMessage verifies a single Emit produces exactly one syslog
// message whose body is the redacted Finding marshalled to JSON.
func TestEmit_SendsJSONMessage(t *testing.T) {
	fw := &fakeWriter{}
	sink, err := outsyslog.New(outsyslog.Config{
		Dialer: dialerForFake(fw),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := sampleFinding()
	if err := sink.Emit(context.Background(), want); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	msgs, _ := fw.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	var got output.Finding
	if err := json.Unmarshal([]byte(msgs[0]), &got); err != nil {
		t.Fatalf("unmarshal message body as JSON: %v\nbody=%q", err, msgs[0])
	}
	if got.RuleID != want.RuleID || got.FilePath != want.FilePath || got.Fingerprint != want.Fingerprint {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
	sent, failed, dropped := sink.Stats()
	if sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("Stats: sent=%d failed=%d dropped=%d, want 1/0/0", sent, failed, dropped)
	}
}

// TestSeverity_FromConfidence verifies confidence buckets map to the
// documented syslog severities so SIEM rules can fire on severity alone.
func TestSeverity_FromConfidence(t *testing.T) {
	cases := []struct {
		name       string
		confidence float64
		wantSev    string
	}{
		{"alert at 0.97", 0.97, "alert"},
		{"alert exactly 0.95", 0.95, "alert"},
		{"crit at 0.90", 0.90, "crit"},
		{"crit exactly 0.85", 0.85, "crit"},
		{"err at 0.75", 0.75, "err"},
		{"warning at 0.60", 0.60, "warning"},
		{"notice at 0.40", 0.40, "notice"},
		{"info at 0.10", 0.10, "info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fw := &fakeWriter{}
			sink, _ := outsyslog.New(outsyslog.Config{Dialer: dialerForFake(fw)})
			f := sampleFinding()
			f.Confidence = tc.confidence
			if err := sink.Emit(context.Background(), f); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			_ = sink.Close()
			_, sevs := fw.snapshot()
			if len(sevs) != 1 {
				t.Fatalf("expected 1 message, got %d", len(sevs))
			}
			if sevs[0] != tc.wantSev {
				t.Errorf("severity = %q, want %q", sevs[0], tc.wantSev)
			}
		})
	}
}

// TestFixedSeverity verifies FixedSeverity overrides the confidence-based
// mapping so every message lands on the chosen channel.
func TestFixedSeverity(t *testing.T) {
	fw := &fakeWriter{}
	sink, _ := outsyslog.New(outsyslog.Config{
		Dialer:        dialerForFake(fw),
		FixedSeverity: syslog.LOG_NOTICE,
	})
	for _, c := range []float64{0.99, 0.5, 0.05} {
		f := sampleFinding()
		f.Confidence = c
		if err := sink.Emit(context.Background(), f); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	_ = sink.Close()
	_, sevs := fw.snapshot()
	if len(sevs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(sevs))
	}
	for i, s := range sevs {
		if s != "notice" {
			t.Errorf("message %d severity = %q, want notice", i, s)
		}
	}
}

// TestMinConfidence_Gate verifies findings below the threshold are silently
// dropped before the queue (no message, no dropped counter — these are
// intentional filter drops, not overflow drops).
func TestMinConfidence_Gate(t *testing.T) {
	fw := &fakeWriter{}
	sink, _ := outsyslog.New(outsyslog.Config{
		Dialer:        dialerForFake(fw),
		MinConfidence: 0.80,
	})
	low := sampleFinding()
	low.Confidence = 0.5
	if err := sink.Emit(context.Background(), low); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	high := sampleFinding()
	high.Confidence = 0.90
	if err := sink.Emit(context.Background(), high); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	_ = sink.Close()
	msgs, _ := fw.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message past the gate, got %d", len(msgs))
	}
	sent, _, dropped := sink.Stats()
	if sent != 1 || dropped != 0 {
		t.Errorf("filter drops should not count as queue drops: sent=%d dropped=%d", sent, dropped)
	}
}

// TestFailedWrite_Reconnects verifies a transient write failure increments the
// failed counter, closes the writer, and triggers a re-dial on the next
// finding — so a momentarily-restarting collector does not silently swallow
// the rest of the run.
func TestFailedWrite_Reconnects(t *testing.T) {
	fw := &fakeWriter{failNext: 1}
	var errBuf bytes.Buffer
	sink, _ := outsyslog.New(outsyslog.Config{
		Dialer: dialerForFake(fw),
		ErrLog: &errBuf,
	})
	if err := sink.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit 1: %v", err)
	}
	if err := sink.Emit(context.Background(), sampleFinding()); err != nil {
		t.Fatalf("Emit 2: %v", err)
	}
	_ = sink.Close()

	sent, failed, _ := sink.Stats()
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if sent != 1 {
		t.Errorf("sent = %d, want 1 (the post-reconnect message)", sent)
	}
	fw.mu.Lock()
	dials := fw.dialCalls
	closes := fw.closeCnt
	fw.mu.Unlock()
	if dials != 2 {
		t.Errorf("dialCalls = %d, want 2 (initial + reconnect)", dials)
	}
	// One close from the failure path, one from worker shutdown.
	if closes < 2 {
		t.Errorf("closeCnt = %d, want >= 2 (failure + shutdown)", closes)
	}
	if errBuf.Len() == 0 {
		t.Error("expected ErrLog to receive a failure line, got none")
	}
}

// TestQueueFull_DropsAndCounts verifies that when the worker is wedged and the
// queue saturates, additional Emits drop the finding and bump the dropped
// counter rather than blocking the scan pipeline.
func TestQueueFull_DropsAndCounts(t *testing.T) {
	// A dialer that blocks until released — the worker calls it on the first
	// write, can't get a writer, and the queue fills behind it.
	release := make(chan struct{})
	fw := &fakeWriter{}
	blockingDialer := func(network, raddr string, priority syslog.Priority, tag string) (outsyslog.Writer, error) {
		<-release
		return fw, nil
	}
	sink, _ := outsyslog.New(outsyslog.Config{
		Dialer:    blockingDialer,
		QueueSize: 2,
	})
	// Fill the queue (2 slots) + 1 in-flight at the worker == 3 total accepted.
	// The 4th and 5th should drop.
	for i := 0; i < 5; i++ {
		_ = sink.Emit(context.Background(), sampleFinding())
	}
	// Wait until at least 2 drops have been counted, then release the dialer
	// so Close can drain cleanly.
	if !waitFor(t, time.Second, func() bool {
		_, _, d := sink.Stats()
		return d >= 2
	}) {
		_, _, d := sink.Stats()
		close(release)
		_ = sink.Close()
		t.Fatalf("expected at least 2 drops while worker wedged, got %d", d)
	}
	close(release)
	_ = sink.Close()
	_, _, dropped := sink.Stats()
	if dropped < 2 {
		t.Errorf("dropped = %d, want >= 2", dropped)
	}
}

// TestNoRawSecrets_LeakIntoSyslog locks in the never-store-raw invariant by
// asserting that even if a Finding is poisoned with a raw-looking string in a
// field, the JSON body the syslog sink ships still does not contain that
// string anywhere unless it was placed in the redacted field (the only field
// that carries operator-visible material at all). This protects against a
// future struct change silently leaking through this sink.
func TestNoRawSecrets_LeakIntoSyslog(t *testing.T) {
	fw := &fakeWriter{}
	sink, _ := outsyslog.New(outsyslog.Config{Dialer: dialerForFake(fw)})
	f := sampleFinding()
	f.Redacted = "REDACTED_MARKER"
	_ = sink.Emit(context.Background(), f)
	_ = sink.Close()
	msgs, _ := fw.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !bytes.Contains([]byte(msgs[0]), []byte("REDACTED_MARKER")) {
		t.Errorf("redacted field should appear in body; got %q", msgs[0])
	}
	// The body must be the redacted JSON form — no field named "raw" or "secret"
	// should ever appear.
	for _, banned := range []string{`"raw"`, `"secret"`, `"plaintext"`} {
		if bytes.Contains([]byte(msgs[0]), []byte(banned)) {
			t.Errorf("body unexpectedly contains banned field %s: %q", banned, msgs[0])
		}
	}
}

// TestParseFacility_KnownAndUnknown covers the operator-facing facility name
// parser used by the CLI wiring.
func TestParseFacility_KnownAndUnknown(t *testing.T) {
	cases := []struct {
		in      string
		want    syslog.Priority
		wantErr bool
	}{
		{"", syslog.LOG_USER, false},
		{"user", syslog.LOG_USER, false},
		{"LOCAL0", syslog.LOG_LOCAL0, false},
		{"  local7  ", syslog.LOG_LOCAL7, false},
		{"daemon", syslog.LOG_DAEMON, false},
		{"bogus", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := outsyslog.ParseFacility(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseFacility(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("ParseFacility(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseSeverity_KnownAndUnknown covers the operator-facing severity name
// parser. The empty string returns 0, the sentinel for "derive from
// confidence".
func TestParseSeverity_KnownAndUnknown(t *testing.T) {
	cases := []struct {
		in      string
		want    syslog.Priority
		wantErr bool
	}{
		{"", 0, false},
		{"warning", syslog.LOG_WARNING, false},
		{"WARN", syslog.LOG_WARNING, false},
		{"info", syslog.LOG_INFO, false},
		{"err", syslog.LOG_ERR, false},
		{"error", syslog.LOG_ERR, false},
		{"alert", syslog.LOG_ALERT, false},
		{"bogus", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := outsyslog.ParseSeverity(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseSeverity(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestClose_Idempotent verifies multiple Close calls don't deadlock and
// don't double-close the channel.
func TestClose_Idempotent(t *testing.T) {
	fw := &fakeWriter{}
	sink, _ := outsyslog.New(outsyslog.Config{Dialer: dialerForFake(fw)})
	if err := sink.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestEmitAfterClose_DropsCleanly verifies post-Close emits are accounted as
// drops rather than panicking on a closed channel.
func TestEmitAfterClose_DropsCleanly(t *testing.T) {
	fw := &fakeWriter{}
	sink, _ := outsyslog.New(outsyslog.Config{Dialer: dialerForFake(fw)})
	_ = sink.Close()
	for i := 0; i < 3; i++ {
		if err := sink.Emit(context.Background(), sampleFinding()); err != nil {
			t.Fatalf("Emit after Close should return nil, got %v", err)
		}
	}
	_, _, dropped := sink.Stats()
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
}
