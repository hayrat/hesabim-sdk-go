package hesabim

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"
	"testing"
	"time"
)

// fetchRecorder is the JWKS origin, as far as a keyCache can tell: it counts
// calls, serves whatever key set the test currently wants, and can be made to
// fail. It is not a stand-in for the code under test — the cache's decisions
// about WHETHER to call it are exactly what is being measured.
type fetchRecorder struct {
	mu      sync.Mutex
	calls   int
	keys    map[string]*ecdsa.PublicKey
	err     error
	release chan struct{} // when non-nil, a fetch blocks until it is closed
	entered chan struct{} // signalled once per fetch, on entry
}

func newFetchRecorder(kids ...string) *fetchRecorder {
	return &fetchRecorder{keys: keySet(kids...), entered: make(chan struct{}, 64)}
}

func keySet(kids ...string) map[string]*ecdsa.PublicKey {
	out := make(map[string]*ecdsa.PublicKey, len(kids))
	for _, kid := range kids {
		// Distinct non-nil pointers: the cache never inspects a key, but the
		// tests must be able to tell "kid a" from "kid b".
		out[kid] = &ecdsa.PublicKey{}
	}
	return out
}

func (f *fetchRecorder) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	f.mu.Lock()
	f.calls++
	release, err, keys := f.release, f.err, f.keys
	f.mu.Unlock()

	// Signalled AFTER calls++ and never before, so a test that has received
	// this has already observed the increment. The send is non-blocking so a
	// test that does not care about entry can never wedge the origin.
	select {
	case f.entered <- struct{}{}:
	default:
	}

	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (f *fetchRecorder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fetchRecorder) setKeys(kids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = keySet(kids...)
}

func (f *fetchRecorder) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// setRelease makes every subsequent fetch block until the returned channel is
// closed, which is how the single-flight tests hold a leader inside the fetch.
func (f *fetchRecorder) setRelease(ch chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.release = ch
}

// newLoadedCache returns a cache that has already had one successful fetch, the
// state every cache is in after New.
//
// The boot fetch's entry signal is DRAINED before returning. Leaving it queued
// would make every later `<-origin.entered` return instantly with a signal from
// setup rather than from the fetch the test is about — a wait that looks like
// synchronisation and provides none.
func newLoadedCache(t *testing.T, clock *testClock, origin *fetchRecorder) *keyCache {
	t.Helper()
	cache := &keyCache{fetch: origin.fetch, now: clock.Now}
	if err := cache.refreshNow(context.Background()); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	origin.drainEntered()
	return cache
}

// drainEntered discards queued fetch-entry signals.
func (f *fetchRecorder) drainEntered() {
	for {
		select {
		case <-f.entered:
		default:
			return
		}
	}
}

// waitForFetchEntry blocks until a fetch has entered the origin, i.e. until
// calls++ has already happened. This is the only sound way to observe work done
// by a goroutine the test did not spawn and cannot join.
func waitForFetchEntry(t *testing.T, origin *fetchRecorder) {
	t.Helper()
	select {
	case <-origin.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no fetch entered the origin within 2s")
	}
}

func TestKeyCache_UnknownKidTriggersARefreshOnceTheFloorHasPassed(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	// The issuer rotates: a new kid appears that this cache has never seen.
	origin.setKeys("old", "new")
	clock.advance(jwksMinRefreshInterval)

	key, err := cache.key(context.Background(), "new")
	if err != nil {
		t.Fatalf("want the rotated key to be picked up, got %v", err)
	}
	if key == nil {
		t.Fatal("want a key, got nil")
	}
	if origin.callCount() != 2 {
		t.Errorf("origin called %d times, want 2 (boot + unknown-kid refresh)", origin.callCount())
	}
}

func TestKeyCache_UnknownKidInsideTheFloorDoesNotFetch(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)
	origin.setKeys("old", "new")

	// One second short of the floor. This is the DoS defence: a made-up kid must
	// not be a free request to the issuer.
	clock.advance(jwksMinRefreshInterval - time.Second)

	_, err := cache.key(context.Background(), "new")
	if !errors.Is(err, errKeysThrottled) {
		t.Fatalf("want errKeysThrottled inside the refresh floor, got %v", err)
	}
	if origin.callCount() != 1 {
		t.Errorf("origin called %d times, want 1 — the floor must suppress the fetch", origin.callCount())
	}

	// And one second later it is allowed again.
	clock.advance(2 * time.Second)
	if _, err := cache.key(context.Background(), "new"); err != nil {
		t.Fatalf("want the refresh to be allowed past the floor, got %v", err)
	}
	if origin.callCount() != 2 {
		t.Errorf("origin called %d times, want 2", origin.callCount())
	}
}

func TestKeyCache_FailedAttemptAlsoAdvancesTheFloor(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	origin.setError(errors.New("issuer is down"))
	clock.advance(jwksMinRefreshInterval)

	if _, err := cache.key(context.Background(), "new"); !errors.Is(err, errKeysUnavailable) {
		t.Fatalf("want errKeysUnavailable, got %v", err)
	}
	if origin.callCount() != 2 {
		t.Fatalf("origin called %d times, want 2", origin.callCount())
	}

	// A failing issuer is exactly when retries would pile up, so the floor must
	// advance on a FAILED attempt too.
	clock.advance(jwksMinRefreshInterval - time.Second)
	if _, err := cache.key(context.Background(), "new"); !errors.Is(err, errKeysThrottled) {
		t.Fatalf("want errKeysThrottled, got %v", err)
	}
	if origin.callCount() != 2 {
		t.Errorf("origin called %d times, want 2 — a failed attempt must still start the floor", origin.callCount())
	}
}

func TestKeyCache_ConcurrentUnknownKidsShareOneFetch(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	origin.setKeys("old", "new")
	release := make(chan struct{})
	origin.setRelease(release)

	clock.advance(jwksMinRefreshInterval)

	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := make(chan struct{})

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = cache.key(context.Background(), "new")
		}()
	}
	close(start)

	// Wait until the single leader is actually inside the fetch, then let the
	// followers pile up behind it before releasing.
	waitForFetchEntry(t, origin)
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if got := origin.callCount(); got != 2 {
		t.Errorf("origin called %d times, want 2 (boot + ONE shared refresh for %d concurrent callers)", got, callers)
	}
}

func TestKeyCache_StaleWhileError(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	// Past the soft TTL, with the issuer unreachable.
	origin.setError(errors.New("issuer is down"))
	clock.advance(jwksSoftTTL + time.Minute)

	key, err := cache.key(context.Background(), "old")
	if err != nil {
		t.Fatalf("a known kid must keep verifying while the issuer is down: %v", err)
	}
	if key == nil {
		t.Fatal("want the cached key, got nil")
	}

	// The background refresh it triggered fails, and that must not empty the
	// cache: the next request still succeeds.
	waitForCalls(t, origin, 2)
	if _, err := cache.key(context.Background(), "old"); err != nil {
		t.Fatalf("a failed refresh must not drop the cached keys: %v", err)
	}
}

func TestKeyCache_SoftTTLRefreshesInTheBackgroundWithoutBlocking(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	origin.setKeys("old", "new")
	clock.advance(jwksSoftTTL)

	// The request is answered from the cache — the new kid is not yet known,
	// which proves the answer did not wait for the refresh.
	if _, err := cache.key(context.Background(), "old"); err != nil {
		t.Fatalf("a soft-stale cache must still answer: %v", err)
	}

	waitForKey(t, cache, "new")

	// Once the background fetch lands, the rotated key is available without any
	// further origin call (the floor has not passed).
	key, err := cache.key(context.Background(), "new")
	if err != nil {
		t.Fatalf("the background refresh should have delivered the rotated key: %v", err)
	}
	if key == nil {
		t.Fatal("want a key, got nil")
	}
	if got := origin.callCount(); got != 2 {
		t.Errorf("origin called %d times, want 2", got)
	}
}

func TestKeyCache_HardTTLFailsClosedEvenForAKnownKid(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	origin.setError(errors.New("issuer is down"))
	clock.advance(jwksHardTTL)

	// This is the bound that makes stale-while-error safe: past it, a key
	// withdrawn in an emergency must stop verifying even though the issuer is
	// unreachable.
	if _, err := cache.key(context.Background(), "old"); err == nil {
		t.Fatal("want a failure past the hard TTL, got nil")
	}

	// And it recovers the moment a refresh succeeds again.
	origin.setError(nil)
	clock.advance(jwksMinRefreshInterval)
	if _, err := cache.key(context.Background(), "old"); err != nil {
		t.Fatalf("a successful refresh must restore verification: %v", err)
	}
}

func TestKeyCache_JustInsideTheHardTTLStillVerifies(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	origin.setError(errors.New("issuer is down"))
	clock.advance(jwksHardTTL - time.Second)

	if _, err := cache.key(context.Background(), "old"); err != nil {
		t.Fatalf("one second inside the hard TTL must still verify: %v", err)
	}
}

func TestKeyCache_RefreshReplacesRatherThanMerges(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("retiring", "current")
	cache := newLoadedCache(t, clock, origin)

	// The issuer withdraws a key. Merging would keep it verifying forever, which
	// is exactly what a revocation has to be able to stop.
	origin.setKeys("current")
	clock.advance(jwksMinRefreshInterval)
	if err := cache.refreshNow(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if _, err := cache.key(context.Background(), "retiring"); err == nil {
		t.Error("a withdrawn key must stop verifying after a refresh")
	}
	if _, err := cache.key(context.Background(), "current"); err != nil {
		t.Errorf("the surviving key must still verify: %v", err)
	}
}

func TestKeyCache_FollowerRespectsItsOwnContext(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	release := make(chan struct{})
	origin.setRelease(release)
	origin.setKeys("old", "new")
	clock.advance(jwksMinRefreshInterval)

	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = cache.key(context.Background(), "new")
	}()

	waitForFetchEntry(t, origin)

	// A follower whose caller gave up must give up too, rather than inheriting
	// the leader's unbounded wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.key(ctx, "new"); err == nil {
		t.Error("want an error for a follower with a cancelled context")
	}

	close(release)
	<-leaderDone
}

// TestKeyCache_LeaderFetchSurvivesCallerCancellation pins the detachment rule:
// the fetch is a shared operation, so the cancellation of the caller that
// happened to become leader must not abort it. Run on the request's context
// instead, an unauthenticated client presenting a made-up kid and dropping the
// connection would abort the fetch AFTER the attempt floor had advanced — one
// such request per minute keeps the cache from ever refreshing again, and past
// the hard TTL that is a full outage.
func TestKeyCache_LeaderFetchSurvivesCallerCancellation(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	release := make(chan struct{})
	origin.setRelease(release)
	origin.setKeys("old", "new")
	clock.advance(jwksMinRefreshInterval)

	ctx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := cache.key(ctx, "new")
		leaderErr <- err
	}()

	waitForFetchEntry(t, origin)
	cancel()

	// The leader stops WAITING with its caller's error...
	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("want the abandoned leader to return context.Canceled, got %v", err)
	}

	// ...but the fetch it started is not aborted. The origin blocks on the
	// fetch's OWN context too (fetchRecorder.fetch selects on ctx.Done), so an
	// implementation that still ran the fetch on the caller's context would
	// have returned ctx.Err() above and "new" could only ever appear through a
	// second fetch — which the call count rules out.
	close(release)
	waitForKey(t, cache, "new")

	if got := origin.callCount(); got != 2 {
		t.Fatalf("origin called %d times, want 2 (boot + the one detached fetch)", got)
	}
}

// waitForCalls blocks until the origin has been called n times. Used only where
// the refresh is a BACKGROUND one that no caller can wait on directly.
func waitForCalls(t *testing.T, origin *fetchRecorder, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if origin.callCount() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("origin was called %d times, want at least %d", origin.callCount(), n)
}

// waitForKey blocks until a background refresh has actually landed in the
// cache. Waiting on the origin call count would be a race: the count rises when
// the fetch STARTS, and the cache is written when it finishes.
func waitForKey(t *testing.T, cache *keyCache, kid string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := cache.lookup(kid); ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("kid %q never appeared in the cache", kid)
}

func TestKeyCache_BackgroundRefreshAdmitsExactlyOneWorker(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	origin := newFetchRecorder("old")
	cache := newLoadedCache(t, clock, origin)

	// The worker is held inside the fetch for the whole burst, so a second
	// admission cannot be excused by "the first one had already finished".
	release := make(chan struct{})
	origin.setRelease(release)
	clock.advance(jwksSoftTTL)

	// A barrier so every caller decides in the same window. This is the shape
	// the bug has in production: a request burst arriving on a soft-stale
	// cache, each request evaluating admission before any of the others has
	// recorded a decision.
	const callers = 64
	admitted := make([]bool, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			admitted[i] = cache.refreshInBackground()
		}()
	}
	close(start)
	wg.Wait()

	started := 0
	for _, ok := range admitted {
		if ok {
			started++
		}
	}
	if started != 1 {
		t.Errorf("%d of %d callers were admitted; the reservation must be claimed under the SAME lock that publishes it, "+
			"or a burst spawns one goroutine per request", started, callers)
	}

	// wg joins the 64 CALLERS, not the worker they admitted, so the count
	// cannot be read yet: the worker is a goroutine this test never spawned and
	// cannot join, and it may not have been scheduled at all. Wait for it to
	// enter the fetch — the signal is sent after the increment — and only then
	// look at the count.
	waitForFetchEntry(t, origin)
	if got := origin.callCount(); got != 2 {
		t.Errorf("origin called %d times, want 2 (boot + one background refresh)", got)
	}

	close(release)
	waitForBackgroundIdle(t, cache)

	// The count is monotonic, so equality here also says it never rose above 2
	// at any point in between: no second worker slipped in behind the first.
	if got := origin.callCount(); got != 2 {
		t.Errorf("origin called %d times by the time the worker finished, want 2", got)
	}

	// The reservation must be RELEASED when the worker finishes; one that leaks
	// would suppress every future background refresh for the life of the
	// process.
	clock.advance(jwksMinRefreshInterval)
	if !cache.refreshInBackground() {
		t.Error("a later background refresh was refused; the reservation was not released")
	}
	waitForBackgroundIdle(t, cache)
}

// waitForBackgroundIdle blocks until no background worker holds the reservation.
func waitForBackgroundIdle(t *testing.T, cache *keyCache) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cache.mu.Lock()
		idle := !cache.bgPending
		cache.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("a background worker never released its reservation")
}
