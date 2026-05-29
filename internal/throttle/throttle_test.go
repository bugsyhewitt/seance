package throttle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestLimiter returns a limiter wired to a virtual clock so the test does
// not actually sleep. now and the channel returned by sleepCh are advanced
// manually via release().
func newTestLimiter(rate float64, burst int) (*Limiter, func(d time.Duration)) {
	var (
		mu       sync.Mutex
		fakeNow  = time.Unix(0, 0)
		releases []chan time.Time
	)
	l := New(rate, burst)
	if l == nil {
		return nil, nil
	}
	l.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return fakeNow
	}
	l.sleepCh = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		defer mu.Unlock()
		ch := make(chan time.Time, 1)
		releases = append(releases, ch)
		return ch
	}
	l.last = fakeNow
	// release advances the virtual clock by d and fires every blocked sleeper.
	release := func(d time.Duration) {
		mu.Lock()
		fakeNow = fakeNow.Add(d)
		toFire := releases
		releases = nil
		now := fakeNow
		mu.Unlock()
		for _, ch := range toFire {
			ch <- now
		}
	}
	return l, release
}

func TestNewRejectsNonPositiveRate(t *testing.T) {
	if got := New(0, 1); got != nil {
		t.Errorf("New(0,1) = %v, want nil", got)
	}
	if got := New(-1, 1); got != nil {
		t.Errorf("New(-1,1) = %v, want nil", got)
	}
}

func TestBurstDefaultsToCeilRate(t *testing.T) {
	l := New(3.5, 0)
	if l.Burst() != 4 {
		t.Errorf("Burst() = %v, want 4", l.Burst())
	}
	if New(0.2, 0).Burst() != 1 {
		t.Errorf("burst floor of 1 not honoured for sub-1 rates")
	}
}

func TestFirstBurstIsImmediate(t *testing.T) {
	// 5 req/s, burst 5 — five back-to-back Wait()s should not block.
	l, _ := newTestLimiter(5, 5)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		waited, err := l.Wait(ctx)
		if err != nil {
			t.Fatalf("Wait #%d: %v", i, err)
		}
		if waited {
			t.Fatalf("Wait #%d unexpectedly throttled within burst", i)
		}
	}
	if got := atomic.LoadUint64(&l.ThrottledRequests); got != 0 {
		t.Errorf("ThrottledRequests=%d after burst, want 0", got)
	}
}

func TestThrottlesAfterBurstExhausted(t *testing.T) {
	// 10 req/s, burst 2. Two go through, the third has to wait.
	l, release := newTestLimiter(10, 2)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if waited, err := l.Wait(ctx); err != nil || waited {
			t.Fatalf("Wait #%d in burst: waited=%v err=%v", i, waited, err)
		}
	}
	// Third Wait should block. Release the virtual clock to unblock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		waited, err := l.Wait(ctx)
		if err != nil {
			t.Errorf("Wait #3: %v", err)
		}
		if !waited {
			t.Errorf("Wait #3: waited=false, want true")
		}
	}()
	// Give the goroutine a moment to actually call Wait and register a sleeper.
	time.Sleep(20 * time.Millisecond)
	release(200 * time.Millisecond)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait #3 did not return after release")
	}
	if got := atomic.LoadUint64(&l.ThrottledRequests); got != 1 {
		t.Errorf("ThrottledRequests=%d, want 1", got)
	}
}

func TestWaitRespectsContextCancellation(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	if _, err := l.Wait(context.Background()); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	// Bucket is now empty; the next Wait should block until ctx cancels.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := l.Wait(ctx)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Wait returned nil err after cancel, want ctx.Err()")
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after context cancel")
	}
}

func TestTransportPassesThroughWhenLimiterAllows(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l := New(1000, 1000) // effectively unlimited for this test
	client := Wrap(l, nil)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do #%d: %v", i, err)
		}
		resp.Body.Close()
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("hits=%d, want 3", hits)
	}
	if got := atomic.LoadUint64(&l.ThrottledRequests); got != 0 {
		t.Errorf("ThrottledRequests=%d, want 0 (no throttling expected at this rate)", got)
	}
}

func TestTransportThrottlesAtConfiguredRate(t *testing.T) {
	// Real (small) wait, real (small) sleep. Not a fake-clock test: we want to
	// prove the underlying time.After path actually pauses RoundTrip. 20 req/s
	// burst 1 means after the first request the second waits ~50ms.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l := New(20, 1)
	client := Wrap(l, nil)

	start := time.Now()
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do #%d: %v", i, err)
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)
	// 4 requests at 20/s with burst 1 ⇒ ~150ms minimum (3 waits of 50ms). Allow
	// generous headroom for CI noise but assert it isn't instant.
	if elapsed < 100*time.Millisecond {
		t.Errorf("4 requests at 20 req/s took only %v, expected >= ~150ms", elapsed)
	}
	if got := atomic.LoadUint64(&l.ThrottledRequests); got != 3 {
		t.Errorf("ThrottledRequests=%d, want 3 (one per delay)", got)
	}
}

func TestTransportPreservesBaseTimeout(t *testing.T) {
	base := &http.Client{Timeout: 7 * time.Second}
	l := New(1, 1)
	wrapped := Wrap(l, base)
	if wrapped.Timeout != 7*time.Second {
		t.Errorf("Wrap dropped base.Timeout: got %v", wrapped.Timeout)
	}
}

func TestWrapNilLimiterReturnsBase(t *testing.T) {
	base := &http.Client{Timeout: 11 * time.Second}
	got := Wrap(nil, base)
	if got != base {
		t.Errorf("Wrap(nil, base) returned a new client; should pass base through")
	}
	if got := Wrap(nil, nil); got == nil {
		t.Errorf("Wrap(nil, nil) returned nil; should return a defaulted client")
	}
}

func TestSharedLimiterCapsAggregateRate(t *testing.T) {
	// The whole point of --rate-limit: a single Limiter shared across multiple
	// clients caps their combined throughput, not each individually.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l := New(10, 1)
	clientA := Wrap(l, nil)
	clientB := Wrap(l, nil)

	start := time.Now()
	var wg sync.WaitGroup
	send := func(c *http.Client, n int) {
		defer wg.Done()
		for i := 0; i < n; i++ {
			req, _ := http.NewRequest("GET", srv.URL, nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Errorf("Do: %v", err)
				return
			}
			resp.Body.Close()
		}
	}
	wg.Add(2)
	go send(clientA, 3)
	go send(clientB, 3)
	wg.Wait()
	elapsed := time.Since(start)

	// 6 requests through a 10 req/s bucket of size 1 ⇒ ~500ms total. Tolerate
	// CI noise: just assert it isn't instant.
	if elapsed < 300*time.Millisecond {
		t.Errorf("6 shared requests took %v, expected >= ~500ms", elapsed)
	}
	if atomic.LoadInt32(&hits) != 6 {
		t.Errorf("hits=%d, want 6", hits)
	}
}
