package hesabim

import "context"

// maxSafeScopeID is 2^53 - 1, the largest integer that survives a JavaScript
// JSON parser intact.
//
// MIRRORED from the mint side, which refuses to issue a scope id outside this
// range. The bound is not about Go — int64 holds far more — it is about the
// fact that the same claim is read by a browser, and a scope id that rounds is
// an authorization check against a place that does not exist. Enforcing the
// same bound here means a token that somehow carries one is rejected rather
// than silently reinterpreted.
const maxSafeScopeID = 1<<53 - 1

// Principal is the verified identity behind a request.
//
// Every field comes from a claim that this issuer stamps on every access token,
// so none of them is optional and none of them is empty: Verify rejects the
// token before building a Principal with a hole in it.
type Principal struct {
	// Subject is `sub`: the user's stable id at the issuer. It is NOT an id in
	// this application's database — the mapping between the two belongs to the
	// application.
	Subject string

	// SessionID is `sid`: the login session this token descends from. Useful
	// for correlating a request with a back-channel logout.
	SessionID string

	// ClientID is `client_id`: which registered application obtained the token.
	// Identifies the caller, never authorizes it.
	ClientID string

	// AMR is `amr`: how the user authenticated, e.g. ["otp"].
	AMR []string

	// ProfileVersion is `hayrat_profile_ver`: the user's profile version at the
	// issuer. Compare it with the version your application stored for this
	// user; when it is larger, refresh the profile you store for this user.
	// 0 when the token carries no (or a malformed) claim, which is how an
	// issuer that predates it looks — so 0 means "unknown", never "refresh".
	ProfileVersion int64

	// Grants is the user's authorization in this token's project: one entry per
	// role, each carrying ITS OWN scopes.
	//
	// # Read this before you touch it
	//
	// The authorization DECISION is always [Principal.Can]. This field is for
	// ENUMERATION — building the WHERE clause for "the districts this user can
	// see", rendering a menu, sizing a page — and nothing else.
	//
	// FLATTENING the grants into independent role and scope lists is FORBIDDEN.
	// A user who is moderator in Ankara and viewer in İzmir flattens to
	// roles=[moderator,viewer], scopes=[Ankara,İzmir], and the most natural
	// check over those two lists authorizes moderator actions in İzmir — a
	// permission nobody granted. The pairing is the contract; it exists in this
	// struct because a resource server genuinely needs to enumerate, and hiding
	// it would only push integrators into parsing the JWT by hand, which is
	// worse. The field is exported on the condition that this paragraph is
	// respected.
	Grants []Grant

	// resolver is copied from the verifier so Can can consult it without the
	// caller having to carry it around. Unexported: a Principal built by hand
	// in a test has exact-match semantics, which is the conservative default.
	resolver ScopeResolver
}

// Grant is one role together with the scopes it applies to.
//
// An EMPTY Scopes means the role is held project-wide. It does not mean "no
// scopes" and it must never be read as "no access": nil and empty are the same
// thing here, and both mean unrestricted within the project. This is the
// asymmetry that makes flattening dangerous — merging a project-wide grant into
// a shared scope list empties the list, and an empty shared list reads as
// unrestricted for every role.
type Grant struct {
	Role   string
	Scopes []Scope
}

// Scope is one place a grant applies to: a type from the issuer's vocabulary
// and a numeric id from its reference data.
type Scope struct {
	Type string
	ID   int64
}

// valid reports whether a scope is something a decision can be made about.
//
// The id bound mirrors the mint side. A zero, negative or oversized id is not a
// place — it is a caller bug or a hand-built target, and the safe answer to a
// question about a place that cannot exist is no.
func (s Scope) valid() bool {
	return s.Type != "" && s.ID >= 1 && s.ID <= maxSafeScopeID
}

// Can reports whether this principal holds `role` over ALL of `targets`.
//
// This is the only authorization primitive this package offers, and the absence
// of the others is the design. There is no HasRole, no InScope, no Roles() —
// each of them lets a caller assemble `hasRole(r) && inScope(t)`, which
// authorizes the cross product of everything the user holds instead of what
// they were actually granted.
//
// The rules, in the order they are applied:
//
//   - A malformed target (empty type, id outside 1..2^53-1) makes the whole call
//     false, before anything else runs. This precedes even the project-wide
//     shortcut: a caller asking about a target it could not construct is a
//     caller whose question is not answerable, and "yes" is the wrong answer to
//     an unanswerable question. It also guarantees a ScopeResolver never sees
//     garbage.
//   - No grant for the role: false.
//   - The grant is project-wide (empty Scopes): true, whatever the targets are.
//   - The grant is scoped and there are NO targets: false. A scoped grant does
//     not authorize a project-wide action; "moderator somewhere" is not
//     "moderator". Only a project-wide grant answers a target-less question.
//   - Otherwise every target must be covered — AND, not OR. Asking about three
//     districts and holding one of them is not permission over the three.
//
// Coverage of a single target is exact match on (Type, ID) over that grant's
// scopes; only if none matches is the ScopeResolver, if any, consulted.
func (p *Principal) Can(role string, targets ...Scope) bool {
	if p == nil {
		return false
	}

	for _, target := range targets {
		if !target.valid() {
			return false
		}
	}

	grant, ok := p.grant(role)
	if !ok {
		return false
	}
	if len(grant.Scopes) == 0 {
		return true
	}
	if len(targets) == 0 {
		return false
	}

	for _, target := range targets {
		if !p.covers(grant.Scopes, target) {
			return false
		}
	}
	return true
}

// grant finds the single grant for a role. The claim contract guarantees at
// most one — Verify rejects a token carrying a role twice — so there is no
// first-match ambiguity to document away.
func (p *Principal) grant(role string) (Grant, bool) {
	for _, g := range p.Grants {
		if g.Role == role {
			return g, true
		}
	}
	return Grant{}, false
}

// covers answers the containment question for one target.
//
// Exact match runs over every granted scope BEFORE the resolver runs over any
// of them. That ordering is the contract's and it is also the cheap one: the
// common case is a grant that names the target exactly, and it must not cost an
// application-provided lookup.
func (p *Principal) covers(granted []Scope, target Scope) bool {
	for _, g := range granted {
		if g.Type == target.Type && g.ID == target.ID {
			return true
		}
	}
	if p.resolver == nil {
		return false
	}
	for _, g := range granted {
		if p.resolver.Covers(g, target) {
			return true
		}
	}
	return false
}

// principalKey is the context key. An unexported empty struct type: no other
// package can produce a value of it, so nothing can plant a Principal in a
// context that this package did not verify.
type principalKey struct{}

// FromContext returns the Principal the middleware verified for this request.
//
// ok is false when there is none, and a handler that ignores ok and calls Can
// on the nil pointer still gets false — the nil receiver is handled — but the
// check is the honest way to notice a route that was never wrapped.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}
