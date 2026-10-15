package hesabim

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"time"
)

// The four numbers that govern key freshness. Each answers a different failure,
// and none of them substitutes for another.
const (
	// jwksSoftTTL is when the cache stops being fresh and starts being merely
	// usable. Past it a request triggers a refresh in the BACKGROUND and is
	// answered from the keys already held: the issuer publishes a new key well
	// before it signs with it (rotation overlap), so a resource server
	// that is 15 minutes behind is still holding the key the token names.
	jwksSoftTTL = 15 * time.Minute

	// jwksHardTTL is when the cache stops being trusted at all. Past it
	// verification fails closed until a refresh succeeds.
	//
	// This bound is the reason stale-while-error is safe to have. Without it,
	// an issuer that becomes unreachable — DNS, firewall, expired certificate —
	// leaves every resource server verifying with a snapshot forever, which
	// means a key withdrawn in an emergency stays valid in exactly the
	// deployments the emergency was about. 24 hours is long enough that a
	// routine outage never reaches it and short enough that a revocation
	// propagates within a day without anyone being paged.
	jwksHardTTL = 24 * time.Hour

	// jwksMinRefreshInterval is the floor between two fetch ATTEMPTS.
	//
	// An unknown kid triggers a synchronous refresh, and an unknown kid is
	// something an attacker can put in a token for free. Without a floor, one
	// unauthenticated request per made-up kid is one request to the issuer's
	// JWKS endpoint — a resource server turned into a load generator against
	// the thing it depends on. The floor advances on EVERY attempt, successful
	// or not, because a failing issuer is precisely when the retries would pile
	// up.
	//
	// The cost is a blind window: a genuinely new kid is refused for up to 60s
	// after the last attempt. Against a ~10 minute access-token lifetime and an
	// issuer that publishes keys before using them, that window is noise.
	jwksMinRefreshInterval = 60 * time.Second

	// jwksRefreshTimeout bounds every JWKS fetch, foreground or background.
	//
	// The fetch always runs on its OWN context (see refreshNow): the fetch is a
	// shared operation whose result every waiter and every later request
	// benefits from, so no single caller's cancellation may abort it. On a
	// request context, one unauthenticated client presenting a made-up kid and
	// dropping the connection would cancel the fetch — and, because the attempt
	// floor advances regardless of outcome, burn the whole 60s window doing it.
	// Repeated once a minute that keeps the cache from ever refreshing again,
	// and past the hard TTL turns it into a full outage.
	//
	// Detached, the fetch needs its own bound: the caller's deadline no longer
	// applies, a custom HTTPClient may have no timeout of its own, and a hung
	// connection would otherwise hold the single-flight slot forever.
	jwksRefreshTimeout = 30 * time.Second
)

// keyCache holds the issuer's verification keys and decides when they may still
// be believed.
//
// Single-flight is implemented with a plain channel rather than a dependency:
// the leader publishes the in-flight channel under the mutex, every arrival
// that finds one waits on it, and the leader closes it after the result is
// already visible in the cache. That ordering is what makes a follower's
// re-read correct — by the time it wakes, the leader's keys are in place.
type keyCache struct {
	fetch func(ctx context.Context) (map[string]*ecdsa.PublicKey, error)
	now   func() time.Time

	mu   sync.Mutex
	keys map[string]*ecdsa.PublicKey

	// fetchedAt is the last SUCCESSFUL fetch; it drives both TTLs. attemptedAt
	// is the last attempt of any outcome; it drives the rate floor. Keeping
	// them apart is the whole point: a failing issuer must not look fresh, and
	// must not be hammered either.
	fetchedAt   time.Time
	attemptedAt time.Time

	inFlight chan struct{}

	// bgPending is the RESERVATION for a background refresh, held from the
	// moment the slot is claimed until the worker finishes.
	//
	// inFlight alone cannot serve this purpose. A goroutine that has been
	// launched but not yet scheduled has not reached refreshNow, so inFlight is
	// still nil, and every other caller in the same burst reads "not busy" and
	// launches its own. Those extra goroutines all collapse onto one fetch —
	// single-flight sees to that — but a request burst on a soft-stale cache
	// would still spawn one goroutine per request, which is a goroutine herd
	// with no upper bound and no benefit. The reservation is taken under the
	// same mutex that publishes it, so the decision and the record of it cannot
	// be separated by a scheduler.
	bgPending bool
}

// key returns the verification key for kid, or the reason it will not.
//
// # The order of the questions
//
// A usable key already in hand answers the request, including when the cache is
// soft-stale — the refresh that case triggers is fire-and-forget and the caller
// never waits for it. Only two situations reach a synchronous fetch: a kid this
// cache has never seen, and a cache too old to trust. Both are exactly the
// situations where serving from memory would be wrong.
//
// # Where stale-while-error lives
//
// It lives in the first branch. A refresh that fails changes nothing about the
// keys already held, so a token naming a KNOWN kid keeps verifying until the
// hard TTL — the issuer being down is not a reason to reject tokens it signed
// while it was up.
func (c *keyCache) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if key, age, ok := c.lookup(kid); ok && age < jwksHardTTL {
		if age >= jwksSoftTTL {
			c.refreshInBackground()
		}
		return key, nil
	}

	refreshErr := c.refreshNow(ctx)

	if key, age, ok := c.lookup(kid); ok && age < jwksHardTTL {
		return key, nil
	}
	if refreshErr != nil {
		return nil, refreshErr
	}
	if _, _, ok := c.lookup(kid); ok {
		// Present but older than the hard TTL, and the refresh reported success
		// without moving fetchedAt — unreachable in practice, and fail-closed
		// if it ever is not.
		return nil, errKeysStale
	}
	return nil, errUnknownKeyID
}

// lookup reads the cache: the key, the age of the key set, and whether the kid
// is there at all.
func (c *keyCache) lookup(kid string) (*ecdsa.PublicKey, time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key, ok := c.keys[kid]
	if !ok {
		return nil, 0, false
	}
	return key, c.now().Sub(c.fetchedAt), true
}

// refreshNow fetches, or waits for the fetch already running, or refuses.
//
// The fetch itself runs DETACHED, on its own bounded context (jwksRefreshTimeout):
// a caller's context governs only how long THAT caller keeps waiting. Leader and
// follower alike may walk away; the fetch completes and the next request finds
// the result.
//
// A follower returns nil rather than the leader's outcome on purpose: "the
// refresh you were waiting for is over" is all it can honestly say, and the
// caller re-reads the cache to find out what that meant for it.
func (c *keyCache) refreshNow(ctx context.Context) error {
	c.mu.Lock()
	if waitFor := c.inFlight; waitFor != nil {
		c.mu.Unlock()
		select {
		case <-waitFor:
			return nil
		case <-ctx.Done():
			// The caller's deadline is the caller's. Abandoning the wait does
			// not abandon the fetch — it is on its own context and the next
			// request will find the result.
			return ctx.Err()
		}
	}
	if !c.attemptedAt.IsZero() && c.now().Sub(c.attemptedAt) < jwksMinRefreshInterval {
		c.mu.Unlock()
		return errKeysThrottled
	}

	done := make(chan struct{})
	c.inFlight = done
	c.attemptedAt = c.now()
	c.mu.Unlock()

	// Written before close(done) and read only after <-done: the channel is
	// the happens-before edge.
	var fetchErr error
	go func() {
		fctx, cancel := context.WithTimeout(context.Background(), jwksRefreshTimeout)
		defer cancel()
		keys, err := c.fetch(fctx)

		c.mu.Lock()
		if err == nil {
			// Replaced wholesale, never merged. A key absent from the new
			// document is a key the issuer withdrew, and merging would keep
			// verifying with it — which is the one thing a revocation has to
			// be able to stop.
			c.keys = keys
			c.fetchedAt = c.now()
		}
		c.inFlight = nil
		c.mu.Unlock()
		fetchErr = err
		close(done)
	}()

	select {
	case <-done:
		if fetchErr != nil {
			return errKeysUnavailable
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// seed is New's boot-time fetch. It differs from refreshNow twice, both times
// deliberately: it reports the underlying cause, because at boot the error
// reaches an operator who has to fix a deployment — "unavailable" alone cannot
// distinguish a 404 jwks_uri from a duplicate kid — and it runs on the caller's
// context, because fail-fast is New's contract and boot is the one caller whose
// cancellation SHOULD abort the fetch.
func (c *keyCache) seed(ctx context.Context) error {
	keys, err := c.fetch(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attemptedAt = c.now()
	if err != nil {
		return err
	}
	c.keys = keys
	c.fetchedAt = c.now()
	return nil
}

// refreshInBackground starts a refresh nobody waits for, and reports whether it
// admitted one.
//
// # The reservation is taken before the goroutine, under the lock
//
// Claiming bgPending and launching the worker are one decision, and the whole
// point is that a burst of callers cannot all pass the check before any of them
// records having done so. Reading the state under the lock and then releasing
// it before the `go` statement would restore exactly the herd this guards
// against: the launched goroutine has not run yet, so nothing it does is
// visible to the callers still deciding.
//
// The bool is the admission decision itself. It is what lets a test assert that
// a burst produced ONE worker rather than inferring it from a fetch count —
// which cannot distinguish "one goroutine" from "sixty goroutines that
// single-flight collapsed onto one fetch".
func (c *keyCache) refreshInBackground() bool {
	c.mu.Lock()
	busy := c.bgPending || c.inFlight != nil ||
		(!c.attemptedAt.IsZero() && c.now().Sub(c.attemptedAt) < jwksMinRefreshInterval)
	if busy {
		c.mu.Unlock()
		return false
	}
	c.bgPending = true
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.bgPending = false
			c.mu.Unlock()
		}()
		// context.Background is about the WAIT, not the fetch — refreshNow
		// detaches the fetch onto its own bounded context regardless. Nothing
		// should ever cancel a refresh no request is waiting on.
		_ = c.refreshNow(context.Background())
	}()
	return true
}
