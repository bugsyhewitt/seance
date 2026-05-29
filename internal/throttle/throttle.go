// Package throttle implements a global, hand-rolled token-bucket rate limiter
// that wraps an http.RoundTripper. It is séance's --rate-limit cap.
//
// Why this exists
//
// séance fans GitHub API calls out across three independent HTTP surfaces — the
// events provider, the targeted/org-scoped Search-API provider, and the diff
// fetcher — each with its own client and its own per-endpoint cadence. The
// existing per-provider adaptive backoffs (X-RateLimit-Remaining / X-Poll-Interval)
// keep each surface inside *its own* quota window, but they are mutually blind:
// a noisy --watch keyword set polling Search-API alongside a force-push-heavy
// fetcher and the events stream can still collectively burst far above what a
// shared GitHub token (or a downstream proxy) is willing to absorb. --rate-limit
// is the single dial that caps the *total* request rate across all three
// surfaces in one place, so an operator who shares a token with another tool, or
// a Docker sidecar squeezed onto a small instance, can set a hard ceiling once
// and have every séance-issued request honour it.
//
// Design
//
//   - The limiter is a classic token bucket: tokens accrue at RatePerSecond
//     tokens/second, capped at Burst (defaults to ceil(rate) so a quiet period
//     does not amortise into an unbounded burst). Each outbound request takes
//     one token; if none is available the call blocks until one accrues, or
//     until the request's context is cancelled — so a SIGINT during a long wait
//     still terminates the run promptly.
//   - It is implemented as an http.RoundTripper that wraps an underlying
//     transport. This lets séance install one shared limiter onto every existing
//     http.Client without touching call sites: every Do() goes through the
//     limiter, the headers, ETag, timeout, and error handling stay where they
//     are. The fairness across the three clients is naturally what stdlib
//     channel-receive scheduling provides (roughly FIFO under contention), which
//     is the right behaviour: no one surface can starve the others.
//   - Zero new dependencies. golang.org/x/time/rate would do the job but adding
//     a module dependency for ~40 lines of token-bucket arithmetic violates the
//     project's tight-dep posture.
//   - The limiter is opt-in: an unset (0) rate means "no throttling, byte-for-byte
//     the prior behaviour", and the pipeline does not even construct the wrapper.
//
// Observability
//
// Every request that had to wait for a token (i.e. the bucket was empty when
// RoundTrip was called) is counted in ThrottledRequests. The pipeline surfaces
// it as rate_limit_throttled_total on the periodic metrics line so an operator
// can tell whether their --rate-limit value is actually binding or just decorative.
package throttle

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Limiter is a token-bucket rate limiter shared across an arbitrary number of
// http.RoundTripper instances. Its zero value is not usable; construct one with
// New.
type Limiter struct {
	ratePerSec float64
	burst      float64

	// now returns the current time. Overridable in tests so token accrual can be
	// driven by a virtual clock without sleeping in unit tests.
	now func() time.Time
	// sleepCh returns a channel that fires after d. Overridable in tests so a
	// virtual clock can release a blocked RoundTrip on demand.
	sleepCh func(d time.Duration) <-chan time.Time

	mu     sync.Mutex
	tokens float64
	last   time.Time

	// ThrottledRequests counts RoundTrip calls that had to wait for a token. A
	// request that took an immediately-available token is not counted — only
	// requests that the limiter actively delayed.
	ThrottledRequests uint64
}

// New returns a Limiter that admits at most ratePerSec requests per second,
// with an initial / maximum burst of burst tokens. If burst <= 0 the burst is
// set to ceil(ratePerSec) (with a floor of 1), which matches the intuitive
// reading of "5 req/s" as "up to 5 in any one-second window after quiescence"
// rather than "unbounded burst after a quiet period". A ratePerSec <= 0 returns
// nil — the caller is expected to skip installing the limiter entirely in the
// no-throttle case rather than getting a no-op wrapper.
func New(ratePerSec float64, burst int) *Limiter {
	if ratePerSec <= 0 {
		return nil
	}
	b := float64(burst)
	if burst <= 0 {
		b = math.Ceil(ratePerSec)
		if b < 1 {
			b = 1
		}
	}
	return &Limiter{
		ratePerSec: ratePerSec,
		burst:      b,
		tokens:     b, // start full so the first burst-worth of requests goes through immediately
		last:       time.Now(),
		now:        time.Now,
		sleepCh:    func(d time.Duration) <-chan time.Time { return time.After(d) },
	}
}

// Rate returns the configured rate (requests/second).
func (l *Limiter) Rate() float64 { return l.ratePerSec }

// Burst returns the configured (or derived) burst size.
func (l *Limiter) Burst() float64 { return l.burst }

// reserve attempts to consume one token. If a token is available immediately it
// returns (0, nil) — the caller proceeds. Otherwise it returns the duration the
// caller should wait before trying again. Pure bookkeeping; never blocks.
func (l *Limiter) reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	elapsed := now.Sub(l.last).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.ratePerSec
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return 0
	}
	// Need (1 - tokens) more tokens; at ratePerSec/sec that takes:
	need := 1 - l.tokens
	wait := time.Duration(need / l.ratePerSec * float64(time.Second))
	// Optimistically reserve the token now and push the next-available timestamp
	// forward; this means concurrent callers queue behind us rather than all
	// racing for the same single accruing token (which would let later callers
	// jump in front under lock-handoff races).
	l.tokens--
	l.last = now.Add(wait)
	return wait
}

// Wait blocks until a token is available or ctx is cancelled. Returns ctx.Err()
// on cancellation. The first return value reports whether the call had to wait
// (so callers can count throttled requests).
func (l *Limiter) Wait(ctx context.Context) (waited bool, err error) {
	wait := l.reserve()
	if wait <= 0 {
		return false, nil
	}
	atomic.AddUint64(&l.ThrottledRequests, 1)
	select {
	case <-l.sleepCh(wait):
		return true, nil
	case <-ctx.Done():
		// Note: we already reserved the token. Returning the token on cancel is
		// possible but adds complexity for negligible benefit — a cancelled run
		// is shutting down, the unreturned token simply means the next run (if
		// it shared the limiter, which it does not) would start one short. The
		// limiter is single-process anyway.
		return true, ctx.Err()
	}
}

// Transport wraps the limiter as an http.RoundTripper. Every call goes through
// Wait before delegating to the underlying transport (defaults to
// http.DefaultTransport).
type Transport struct {
	Limiter *Limiter
	Base    http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Limiter == nil {
		// Defensive: a nil limiter means "no throttling". Pass through.
		return t.base().RoundTrip(req)
	}
	if _, err := t.Limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	return t.base().RoundTrip(req)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// Wrap returns an *http.Client whose Transport throttles through l. The
// underlying transport (timeout, etc) is preserved from base — Wrap copies
// base's Timeout and CheckRedirect onto the returned client and installs the
// throttling Transport. If base is nil a fresh http.Client with a 30s timeout
// is used as the underlying client (matching séance's other client defaults).
func Wrap(l *Limiter, base *http.Client) *http.Client {
	if l == nil {
		if base != nil {
			return base
		}
		return &http.Client{Timeout: 30 * time.Second}
	}
	var underlying http.RoundTripper
	timeout := 30 * time.Second
	var redirect func(req *http.Request, via []*http.Request) error
	if base != nil {
		underlying = base.Transport
		if base.Timeout > 0 {
			timeout = base.Timeout
		}
		redirect = base.CheckRedirect
	}
	return &http.Client{
		Transport:     &Transport{Limiter: l, Base: underlying},
		Timeout:       timeout,
		CheckRedirect: redirect,
	}
}

// ErrLimiterClosed is reserved for future use should the limiter ever need to
// be torn down while requests are blocked; currently the limiter has no
// lifecycle and Wait only returns ctx.Err() on cancellation.
var ErrLimiterClosed = errors.New("throttle: limiter closed")
