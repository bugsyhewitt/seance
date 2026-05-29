// Package webhookrecv implements a scan-on-push ingestion provider for séance.
// Where the events provider polls GitHub's global firehose and the search
// provider polls the indexed search corpus, this provider runs an inbound HTTP
// server and reacts to GitHub push webhook deliveries the instant they arrive —
// no polling, no rate-limit budget, and near-zero latency from push to scan.
//
// It is the natural fit for the case where you control the repos (or an org/app
// is configured to deliver to you): point a GitHub webhook (or a GitHub App's
// "push" event) at séance and every push is scanned immediately, off the events
// firehose's bounded, delayed window entirely. It is a complementary coverage
// axis, additive at the ingestion edge — it implements the same
// ingestion.Provider interface and fans CommitEvents into the identical
// downstream prefilter → fetch → scan → dedup → sink pipeline.
//
// Security posture:
//
//   - When a secret is configured (--webhook-listen-secret, or the GitHub webhook
//     "Secret" field), every delivery's X-Hub-Signature-256 HMAC is verified with
//     a constant-time compare before the body is parsed. An invalid or missing
//     signature is rejected with 401 and counted. Running without a secret is
//     allowed (a private network / sidecar deployment) but logged as a warning.
//   - The provider never emits raw secrets: like every other provider it emits
//     only CommitEvents (repo + SHA + changed-file metadata). Content fetching and
//     redaction happen downstream exactly as for the events/search providers.
//
// Only the "push" event is acted on. A "ping" (GitHub's webhook-setup probe) is
// answered 200 OK so the GitHub UI shows a green check. Every other event type is
// acknowledged 200 OK and ignored — séance is a push scanner, not a generic
// webhook router.
package webhookrecv

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

const (
	userAgent = "seance/0.1 (+https://github.com/bugsyhewitt/seance)"

	// defaultPath is the URL path the receiver handles. A GitHub webhook can be
	// pointed at any path; this is the conventional default. Overridable via Config.
	defaultPath = "/webhook"

	// maxBodyBytes caps the request body séance will read from a single delivery.
	// GitHub push payloads are small (the commits array, when present, is trimmed);
	// this bounds memory against a malicious or runaway sender. 5 MiB is generous.
	maxBodyBytes = 5 << 20

	// shutdownGrace bounds how long Stream waits for in-flight deliveries to drain
	// when the context is cancelled before forcing the listener closed.
	shutdownGrace = 5 * time.Second
)

// zeroSHA is the all-zero object name GitHub uses for branch creation (as
// "before") and branch deletion (as "head").
const zeroSHA = "0000000000000000000000000000000000000000"

// Metrics holds live instrumentation counters. All fields are updated atomically.
type Metrics struct {
	DeliveriesReceived  uint64 // total HTTP deliveries accepted at the handler
	SignaturesRejected  uint64 // deliveries rejected for a bad/missing signature
	PushEventsReceived  uint64 // push deliveries parsed
	ForcePushesReceived uint64 // force-push deliveries detected and emitted
	CommitsEmitted      uint64 // total CommitEvents sent downstream
}

// Config configures the receiver. Addr and Secret are typically supplied from
// CLI flags; the rest have sensible defaults.
type Config struct {
	// Addr is the TCP address to listen on, e.g. ":8099" or "127.0.0.1:8099".
	Addr string
	// Path is the URL path to handle. Empty defaults to "/webhook".
	Path string
	// Secret is the shared HMAC secret configured on the GitHub webhook. When
	// non-empty, X-Hub-Signature-256 is verified on every delivery. When empty,
	// signatures are not checked (logged as a warning on start).
	Secret string
	// DetectForcePush mirrors the events provider: when true, force-push deliveries
	// are emitted as ForcePush-flagged CommitEvents carrying the before SHA so the
	// fetcher recovers the orphaned diff. Defaults to true via New.
	DetectForcePush bool
	// ErrLog receives operational log lines. Defaults to os.Stderr via New.
	ErrLog io.Writer
}

// Provider is an ingestion.Provider that scans on inbound GitHub push webhooks.
type Provider struct {
	cfg     Config
	Metrics Metrics
}

// New returns a webhook-receiver provider listening on addr. A blank secret
// disables signature verification (allowed, but warned about on start). path
// blank defaults to "/webhook".
func New(addr, path, secret string) *Provider {
	if path == "" {
		path = defaultPath
	}
	return &Provider{
		cfg: Config{
			Addr:            addr,
			Path:            path,
			Secret:          secret,
			DetectForcePush: true,
			ErrLog:          os.Stderr,
		},
	}
}

// Name implements ingestion.Provider.
func (p *Provider) Name() string { return "webhook-receiver" }

// Path returns the URL path the receiver handles (after defaulting).
func (p *Provider) Path() string { return p.cfg.Path }

// Stream implements ingestion.Provider. It starts an HTTP server bound to the
// configured address and emits a CommitEvent for every commit in every verified
// push delivery until ctx is cancelled (graceful drain) or the listener fails to
// bind (single error, then close). Both channels are always closed on exit.
func (p *Provider) Stream(ctx context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
	events := make(chan ingestion.CommitEvent, 64)
	errs := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(p.cfg.Path, func(w http.ResponseWriter, r *http.Request) {
		p.handle(w, r, events)
	})
	srv := &http.Server{
		Addr:              p.cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if p.cfg.Secret == "" {
		fmt.Fprintf(p.errLog(), "séance: WARNING — webhook receiver running WITHOUT a secret; delivery signatures are NOT verified. Set --webhook-listen-secret in any untrusted network.\n")
	}

	go func() {
		defer close(events)
		defer close(errs)

		serveErr := make(chan error, 1)
		go func() {
			fmt.Fprintf(p.errLog(), "séance: webhook receiver listening on %s%s — scanning inbound GitHub pushes\n", p.cfg.Addr, p.cfg.Path)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serveErr <- err
				return
			}
			serveErr <- nil
		}()

		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
			<-serveErr // wait for ListenAndServe to return
		case err := <-serveErr:
			if err != nil {
				select {
				case errs <- fmt.Errorf("webhook receiver: %w", err):
				default:
				}
			}
		}
	}()

	return events, errs
}

func (p *Provider) errLog() io.Writer {
	if p.cfg.ErrLog != nil {
		return p.cfg.ErrLog
	}
	return os.Stderr
}

// handle processes a single inbound delivery. It verifies the signature (when a
// secret is configured), then dispatches on the X-GitHub-Event header. Only
// "push" is scanned; "ping" returns 200 (so the GitHub UI shows a green check);
// any other event type is acknowledged and ignored.
func (p *Provider) handle(w http.ResponseWriter, r *http.Request, events chan<- ingestion.CommitEvent) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	atomic.AddUint64(&p.Metrics.DeliveriesReceived, 1)

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if p.cfg.Secret != "" {
		if !validSignature(p.cfg.Secret, r.Header.Get("X-Hub-Signature-256"), body) {
			atomic.AddUint64(&p.Metrics.SignaturesRejected, 1)
			fmt.Fprintf(p.errLog(), "séance: webhook delivery rejected — invalid or missing X-Hub-Signature-256\n")
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
	}

	switch r.Header.Get("X-GitHub-Event") {
	case "ping":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"pong":true}`))
		return
	case "push":
		atomic.AddUint64(&p.Metrics.PushEventsReceived, 1)
		n := p.parsePush(body, events)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"ok":true,"commits_queued":%d}`, n)
		return
	default:
		// Acknowledge and ignore — séance is a push scanner, not a router.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"ignored":true}`))
		return
	}
}

// validSignature reports whether sigHeader is a valid GitHub-style
// "sha256=<hex>" HMAC of body under secret. The compare is constant-time and the
// header is parsed defensively (missing prefix, bad hex, wrong length all fail
// without panicking or leaking timing on the prefix check).
func validSignature(secret, sigHeader string, body []byte) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(sigHeader, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := mac.Sum(nil)
	return hmac.Equal(got, want)
}

// pushPayload mirrors the relevant fields of a GitHub push webhook payload. It is
// intentionally a superset of the events-API push shape: webhook deliveries carry
// repository.full_name and a richer commits array (sha/message/author/added/
// modified/removed) plus before/after/ref/forced — so we can populate file lists
// directly when present and fall back to the head SHA otherwise, exactly like the
// events provider.
type pushPayload struct {
	Ref     string `json:"ref"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Forced  bool   `json:"forced"`
	Created bool   `json:"created"`
	Deleted bool   `json:"deleted"`
	Repo    struct {
		FullName string `json:"full_name"`
		Owner    struct {
			Name  string `json:"name"`
			Login string `json:"login"`
		} `json:"owner"`
		Name string `json:"name"`
	} `json:"repository"`
	Pusher struct {
		Name string `json:"name"`
	} `json:"pusher"`
	HeadCommit *struct {
		ID string `json:"id"`
	} `json:"head_commit"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"commits"`
}

// parsePush parses a push delivery body and emits one CommitEvent per scannable
// commit. It returns the number of events emitted. When the commits array is
// present (the common webhook case) each commit's file lists are carried through
// with FilesKnown=true so the fetcher need not rediscover them. When the commits
// array is absent (large pushes truncate it) it falls back to the head SHA with
// FilesKnown=false, exactly like the events provider's new-format path. A
// force-push is emitted as a single ForcePush-flagged event carrying the before
// SHA so the fetcher recovers the orphaned diff.
func (p *Provider) parsePush(body []byte, events chan<- ingestion.CommitEvent) int {
	var push pushPayload
	if err := json.Unmarshal(body, &push); err != nil {
		fmt.Fprintf(p.errLog(), "séance: webhook push decode error: %v\n", err)
		return 0
	}

	owner, name := p.repoOwnerName(push)
	if owner == "" {
		fmt.Fprintf(p.errLog(), "séance: webhook push missing repository.full_name — skipping\n")
		return 0
	}
	ts := time.Now()

	// Force-push: HEAD reset backward onto a now-dangling tip. Emit one flagged
	// event carrying the before SHA. Branch creation/deletion have no recoverable
	// prior tip, so they are excluded (handled inside isForcePush).
	if p.cfg.DetectForcePush && isForcePush(push.Forced, push.Created, push.Deleted, push.Before, push.After) {
		events <- ingestion.CommitEvent{
			Provider:   "webhook",
			RepoOwner:  owner,
			RepoName:   name,
			CommitSHA:  push.After,
			AuthorName: push.Pusher.Name,
			FilesKnown: false,
			ForcePush:  true,
			BeforeSHA:  push.Before,
			Timestamp:  ts,
		}
		atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
		atomic.AddUint64(&p.Metrics.ForcePushesReceived, 1)
		return 1
	}

	// Branch deletion has nothing to scan.
	if push.Deleted || push.After == zeroSHA {
		return 0
	}

	if len(push.Commits) > 0 {
		emitted := 0
		for _, c := range push.Commits {
			if c.ID == "" {
				continue
			}
			var files []ingestion.FileRef
			for _, f := range c.Added {
				files = append(files, ingestion.FileRef{Path: f, Status: "added"})
			}
			for _, f := range c.Modified {
				files = append(files, ingestion.FileRef{Path: f, Status: "modified"})
			}
			for _, f := range c.Removed {
				files = append(files, ingestion.FileRef{Path: f, Status: "removed"})
			}
			events <- ingestion.CommitEvent{
				Provider:    "webhook",
				RepoOwner:   owner,
				RepoName:    name,
				CommitSHA:   c.ID,
				CommitMsg:   c.Message,
				AuthorName:  c.Author.Name,
				AuthorEmail: c.Author.Email,
				Files:       files,
				FilesKnown:  true,
				Timestamp:   ts,
			}
			atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
			emitted++
		}
		return emitted
	}

	// Commits array absent (truncated for a large push) — fall back to the head
	// SHA and let the fetcher discover the changed files.
	head := push.After
	if push.HeadCommit != nil && push.HeadCommit.ID != "" {
		head = push.HeadCommit.ID
	}
	if head == "" || head == zeroSHA {
		return 0
	}
	events <- ingestion.CommitEvent{
		Provider:   "webhook",
		RepoOwner:  owner,
		RepoName:   name,
		CommitSHA:  head,
		AuthorName: push.Pusher.Name,
		FilesKnown: false,
		Timestamp:  ts,
	}
	atomic.AddUint64(&p.Metrics.CommitsEmitted, 1)
	return 1
}

// repoOwnerName extracts owner and repo name from the payload, preferring the
// explicit full_name ("owner/repo") and falling back to the owner.login/name
// fields GitHub also populates.
func (p *Provider) repoOwnerName(push pushPayload) (owner, name string) {
	if full := push.Repo.FullName; full != "" {
		if i := strings.IndexByte(full, '/'); i >= 0 {
			return full[:i], full[i+1:]
		}
		return full, ""
	}
	owner = push.Repo.Owner.Login
	if owner == "" {
		owner = push.Repo.Owner.Name
	}
	return owner, push.Repo.Name
}

// isForcePush reports whether a webhook push payload has the force-push
// (history-rewrite) shape: HEAD moved off a real prior tip that is now dangling.
// True when the forced flag is set with a real before/after pair. Branch creation
// (created, or before == zero) and deletion (deleted, or after == zero) are
// excluded — there is no recoverable orphaned tip.
func isForcePush(forced, created, deleted bool, before, after string) bool {
	if !forced {
		return false
	}
	if created || deleted {
		return false
	}
	if before == "" || after == "" || before == after {
		return false
	}
	if before == zeroSHA || after == zeroSHA {
		return false
	}
	return true
}
