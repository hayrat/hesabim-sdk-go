package hesabim

import (
	"context"
	"testing"
)

// recordingResolver answers a fixed containment rule and records every call, so
// a test can assert both the answer and whether the resolver was consulted at
// all — "exact match first" and "never called with a malformed target" are
// claims about the CALLS, not about the result.
type recordingResolver struct {
	covers func(granted, target Scope) bool
	calls  [][2]Scope
}

func (r *recordingResolver) Covers(granted, target Scope) bool {
	r.calls = append(r.calls, [2]Scope{granted, target})
	if r.covers == nil {
		return false
	}
	return r.covers(granted, target)
}

// province6 covers every district when the resolver is asked. The SDK does not
// know this relationship; the application does.
func provinceCoversDistrict(granted, target Scope) bool {
	return granted.Type == ScopeTypeProvince && granted.ID == 6 &&
		target.Type == ScopeTypeDistrict && target.ID/100 == 6
}

func principalWith(grants ...Grant) *Principal {
	return &Principal{Subject: "s", SessionID: "sid", ClientID: "c", AMR: []string{"otp"}, Grants: grants}
}

func TestCan_ExactMatchTable(t *testing.T) {
	t.Parallel()

	ankara := Scope{Type: ScopeTypeProvince, ID: 6}
	izmir := Scope{Type: ScopeTypeProvince, ID: 35}
	cankaya := Scope{Type: ScopeTypeDistrict, ID: 601}

	// The canonical example token: moderator in Ankara, viewer in
	// İzmir. Every dangerous combination is below.
	crossProduct := principalWith(
		Grant{Role: "moderator", Scopes: []Scope{ankara}},
		Grant{Role: "viewer", Scopes: []Scope{izmir}},
	)

	cases := []struct {
		name      string
		principal *Principal
		role      string
		targets   []Scope
		want      bool
	}{
		{"granted role over the granted scope", crossProduct, "moderator", []Scope{ankara}, true},
		{"THE CROSS PRODUCT: moderator over the viewer's province", crossProduct, "moderator", []Scope{izmir}, false},
		{"the other direction", crossProduct, "viewer", []Scope{ankara}, false},
		{"viewer over its own province", crossProduct, "viewer", []Scope{izmir}, true},
		{"a role nobody granted", crossProduct, "admin", []Scope{ankara}, false},
		{"empty role name", crossProduct, "", []Scope{ankara}, false},
		{"a scoped grant asked without a target", crossProduct, "moderator", nil, false},
		{"the right id under the wrong type", crossProduct, "moderator", []Scope{{Type: ScopeTypeDistrict, ID: 6}}, false},
		{"the right type with the wrong id", crossProduct, "moderator", []Scope{{Type: ScopeTypeProvince, ID: 7}}, false},
		{"a district under a province grant, without a resolver", crossProduct, "moderator", []Scope{cankaya}, false},

		{
			name:      "a project-wide grant covers any target",
			principal: principalWith(Grant{Role: "viewer"}),
			role:      "viewer", targets: []Scope{izmir}, want: true,
		},
		{
			name:      "a project-wide grant answers a target-less question",
			principal: principalWith(Grant{Role: "viewer"}),
			role:      "viewer", targets: nil, want: true,
		},
		{
			name:      "a project-wide grant covers several targets at once",
			principal: principalWith(Grant{Role: "viewer"}),
			role:      "viewer", targets: []Scope{ankara, izmir, cankaya}, want: true,
		},
		{
			name:      "an explicitly empty scope list is project-wide too",
			principal: principalWith(Grant{Role: "viewer", Scopes: []Scope{}}),
			role:      "viewer", targets: nil, want: true,
		},
		{
			name: "a project-wide grant for ANOTHER role does not widen this one",
			principal: principalWith(
				Grant{Role: "moderator", Scopes: []Scope{ankara}},
				Grant{Role: "viewer"},
			),
			role: "moderator", targets: []Scope{izmir}, want: false,
		},

		{
			name:      "several targets, all covered",
			principal: principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara, izmir}}),
			role:      "moderator", targets: []Scope{ankara, izmir}, want: true,
		},
		{
			name:      "several targets, one uncovered — AND, not OR",
			principal: principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}}),
			role:      "moderator", targets: []Scope{ankara, izmir}, want: false,
		},
		{
			name:      "several targets, the uncovered one first",
			principal: principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}}),
			role:      "moderator", targets: []Scope{izmir, ankara}, want: false,
		},

		{name: "a nil principal grants nothing", principal: nil, role: "viewer", targets: nil, want: false},
		{
			name:      "a principal with no grants at all",
			principal: principalWith(),
			role:      "viewer", targets: []Scope{ankara}, want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := c.principal.Can(c.role, c.targets...); got != c.want {
				t.Errorf("Can(%q, %v) = %v, want %v", c.role, c.targets, got, c.want)
			}
		})
	}
}

func TestCan_MalformedTargetIsRefusedWithoutConsultingTheResolver(t *testing.T) {
	t.Parallel()

	ankara := Scope{Type: ScopeTypeProvince, ID: 6}

	cases := []struct {
		name   string
		target Scope
	}{
		{"empty type", Scope{Type: "", ID: 6}},
		{"zero id", Scope{Type: ScopeTypeProvince, ID: 0}},
		{"negative id", Scope{Type: ScopeTypeProvince, ID: -1}},
		{"id above the safe range", Scope{Type: ScopeTypeProvince, ID: maxSafeScopeID + 1}},
		{"empty everything", Scope{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// A resolver that says yes to everything. If the malformed target
			// reached it, the answer would be true.
			resolver := &recordingResolver{covers: func(Scope, Scope) bool { return true }}

			t.Run("with a scoped grant", func(t *testing.T) {
				p := principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}})
				p.resolver = resolver
				if p.Can("moderator", c.target) {
					t.Error("a malformed target must never be authorized")
				}
			})

			t.Run("with a project-wide grant", func(t *testing.T) {
				// The project-wide shortcut does NOT rescue a malformed target:
				// a question about a place that cannot exist has no yes answer.
				p := principalWith(Grant{Role: "viewer"})
				p.resolver = resolver
				if p.Can("viewer", c.target) {
					t.Error("a malformed target must not be authorized by a project-wide grant either")
				}
			})

			t.Run("alongside a valid target", func(t *testing.T) {
				p := principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}})
				p.resolver = resolver
				if p.Can("moderator", ankara, c.target) {
					t.Error("one malformed target must sink the whole call")
				}
			})

			if len(resolver.calls) != 0 {
				t.Errorf("the resolver was called %d times with a malformed target in play: %v", len(resolver.calls), resolver.calls)
			}
		})
	}
}

func TestCan_ResolverIsConsultedOnlyAfterExactMatchFails(t *testing.T) {
	t.Parallel()

	ankara := Scope{Type: ScopeTypeProvince, ID: 6}
	cankaya := Scope{Type: ScopeTypeDistrict, ID: 601}
	izmirDistrict := Scope{Type: ScopeTypeDistrict, ID: 3501}

	t.Run("exact match short-circuits", func(t *testing.T) {
		t.Parallel()
		resolver := &recordingResolver{covers: func(Scope, Scope) bool { return true }}
		p := principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}})
		p.resolver = resolver

		if !p.Can("moderator", ankara) {
			t.Fatal("an exactly granted scope must be authorized")
		}
		if len(resolver.calls) != 0 {
			t.Errorf("the resolver must not be consulted when exact match succeeds; %d calls", len(resolver.calls))
		}
	})

	t.Run("resolver widens a province to its districts", func(t *testing.T) {
		t.Parallel()
		resolver := &recordingResolver{covers: provinceCoversDistrict}
		p := principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}})
		p.resolver = resolver

		if !p.Can("moderator", cankaya) {
			t.Error("the resolver said the province covers the district; Can must agree")
		}
		if len(resolver.calls) != 1 {
			t.Fatalf("want exactly one resolver call, got %d", len(resolver.calls))
		}
		// Argument ORDER is load-bearing: an implementation that swapped them
		// would ask "does the district cover the province".
		if resolver.calls[0][0] != ankara || resolver.calls[0][1] != cankaya {
			t.Errorf("resolver called with (granted=%v, target=%v), want (granted=%v, target=%v)",
				resolver.calls[0][0], resolver.calls[0][1], ankara, cankaya)
		}
	})

	t.Run("resolver refusing means denied", func(t *testing.T) {
		t.Parallel()
		resolver := &recordingResolver{covers: provinceCoversDistrict}
		p := principalWith(Grant{Role: "moderator", Scopes: []Scope{ankara}})
		p.resolver = resolver

		if p.Can("moderator", izmirDistrict) {
			t.Error("a district outside the granted province must be denied")
		}
	})

	t.Run("the resolver is offered every granted scope", func(t *testing.T) {
		t.Parallel()
		other := Scope{Type: ScopeTypeProvince, ID: 35}
		resolver := &recordingResolver{covers: provinceCoversDistrict}
		p := principalWith(Grant{Role: "moderator", Scopes: []Scope{other, ankara}})
		p.resolver = resolver

		if !p.Can("moderator", cankaya) {
			t.Error("the second granted scope covers the target; Can must find it")
		}
		if len(resolver.calls) != 2 {
			t.Errorf("want the resolver offered both granted scopes, got %d calls", len(resolver.calls))
		}
	})

	t.Run("the resolver does not rescue a role nobody granted", func(t *testing.T) {
		t.Parallel()
		resolver := &recordingResolver{covers: func(Scope, Scope) bool { return true }}
		p := principalWith(Grant{Role: "viewer", Scopes: []Scope{ankara}})
		p.resolver = resolver

		if p.Can("moderator", cankaya) {
			t.Error("scope containment must not stand in for a missing role")
		}
		if len(resolver.calls) != 0 {
			t.Errorf("the resolver must not be reached without a matching grant; %d calls", len(resolver.calls))
		}
	})
}

func TestCan_ResolverFromConfigReachesThePrincipal(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)

	resolver := &recordingResolver{covers: provinceCoversDistrict}
	v := newTestVerifier(t, idp, clock, func(cfg *Config) { cfg.Resolver = resolver })

	claims := validClaims(idp.issuer(), clock.Now())
	claims[claimGrants] = []any{grantClaim("moderator", scopeClaim(ScopeTypeProvince, 6))}

	principal, err := v.Verify(context.Background(), key.sign(t, claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Without the wiring this is false: the resolver is the only thing that can
	// turn a province grant into a district permission.
	if !principal.Can("moderator", Scope{Type: ScopeTypeDistrict, ID: 601}) {
		t.Error("the configured resolver must be consulted by a Principal that Verify built")
	}
}

func TestFromContext(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		p, ok := FromContext(context.Background())
		if ok {
			t.Error("want ok=false for a context the middleware never touched")
		}
		// A handler that ignores ok must still be safe.
		if p.Can("viewer") {
			t.Error("a nil principal must authorize nothing")
		}
	})

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		want := principalWith(Grant{Role: "viewer"})
		ctx := context.WithValue(context.Background(), principalKey{}, want)

		got, ok := FromContext(ctx)
		if !ok {
			t.Fatal("want ok=true")
		}
		if got != want {
			t.Error("FromContext returned a different principal than the one stored")
		}
	})

	t.Run("a nil principal under the key is not a principal", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), principalKey{}, (*Principal)(nil))
		if _, ok := FromContext(ctx); ok {
			t.Error("want ok=false for a nil principal")
		}
	})
}

func TestScopeValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		scope Scope
		want  bool
	}{
		{Scope{Type: ScopeTypeProvince, ID: 1}, true},
		{Scope{Type: ScopeTypeProvince, ID: maxSafeScopeID}, true},
		{Scope{Type: "anything-non-empty", ID: 1}, true},
		{Scope{Type: "", ID: 1}, false},
		{Scope{Type: ScopeTypeProvince, ID: 0}, false},
		{Scope{Type: ScopeTypeProvince, ID: -1}, false},
		{Scope{Type: ScopeTypeProvince, ID: maxSafeScopeID + 1}, false},
	}

	for _, c := range cases {
		if got := c.scope.valid(); got != c.want {
			t.Errorf("Scope%+v.valid() = %v, want %v", c.scope, got, c.want)
		}
	}
}
