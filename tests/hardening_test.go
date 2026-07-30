package tests

import (
	"context"
	"testing"
	"time"

	"are/core"
)

func validArtifact(claims ...core.Claim) core.AuthorityArtifact {
	nodes := make(map[string]core.Claim, len(claims))
	for _, claim := range claims {
		nodes[claim.ID] = claim
	}
	return core.AuthorityArtifact{
		ID:          "artifact",
		SourceID:    "source",
		Claims:      claims,
		Graph:       core.AuthorityGraph{Nodes: nodes, Edges: []core.Edge{}},
		GeneratedAt: time.Now().UTC(),
	}
}

func baseClaim() map[string]interface{} {
	return map[string]interface{}{
		"id":       "allow",
		"type":     "permission",
		"subject":  "user",
		"action":   "read",
		"resource": "/data",
		"scope":    map[string]interface{}{},
	}
}

func sourceWithClaims(id string, claims interface{}) core.AuthoritySource {
	return core.AuthoritySource{
		ID:      id,
		Type:    core.Legal,
		Name:    "Authority",
		Version: "1.0.0",
		Metadata: map[string]interface{}{
			"claims": claims,
		},
	}
}

func requireCompilationFailure(t *testing.T, result interface{}) {
	t.Helper()
	if _, ok := result.(core.CompilationFailure); !ok {
		t.Fatalf("expected fail-closed CompilationFailure, got %T", result)
	}
}

func TestMalformedAuthorityInputFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		claims interface{}
	}{
		{name: "claims container", claims: "not-a-list"},
		{name: "claim entry", claims: []interface{}{"not-a-map"}},
		{name: "scope", claims: []interface{}{func() map[string]interface{} {
			claim := baseClaim()
			claim["scope"] = "US-only"
			return claim
		}()}},
		{name: "conditions", claims: []interface{}{func() map[string]interface{} {
			claim := baseClaim()
			claim["conditions"] = "mfa-required"
			return claim
		}()}},
		{name: "relation value", claims: []interface{}{func() map[string]interface{} {
			claim := baseClaim()
			claim["conditions"] = map[string]interface{}{"revokes": 42}
			return claim
		}()}},
		{name: "dangling relation", claims: []interface{}{func() map[string]interface{} {
			claim := baseClaim()
			claim["conditions"] = map[string]interface{}{"revokes": "missing"}
			return claim
		}()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiler := core.NewAuthorityCompiler()
			requireCompilationFailure(t, compiler.Process(sourceWithClaims("source", test.claims)))
		})
	}
}

func TestConflictingSourceRedefinitionFailsClosed(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	first := sourceWithClaims("source", []interface{}{})
	if _, err := compiler.Normalize(context.Background(), first); err != nil {
		t.Fatalf("first normalization failed: %v", err)
	}
	second := first
	second.Type = core.Contractual
	if _, err := compiler.Normalize(context.Background(), second); err == nil {
		t.Fatal("conflicting redefinition of immutable authority source must fail")
	}
}

func TestNilLoggerFallsBackToSafeDefault(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	compiler.SetLogger(nil)
	if _, ok := compiler.Process(sourceWithClaims("source", []interface{}{})).(core.CompilationSuccess); !ok {
		t.Fatal("nil logger should use the safe no-op logger")
	}
}

func TestRelationshipMetadataCannotEraseProhibition(t *testing.T) {
	for _, relationship := range []string{"delegates_to", "revokes", "supersedes"} {
		t.Run(relationship, func(t *testing.T) {
			allow := baseClaim()
			allow["conditions"] = map[string]interface{}{relationship: "deny"}
			deny := baseClaim()
			deny["id"] = "deny"
			deny["type"] = "prohibition"

			compiler := core.NewAuthorityCompiler()
			requireCompilationFailure(t, compiler.Process(sourceWithClaims(
				"source",
				[]interface{}{allow, deny},
			)))
		})
	}
}

func TestGraphMustExactlyMatchClaims(t *testing.T) {
	claim := core.Claim{
		ID: "allow", Type: core.Permission, Subject: "user", Action: "read",
		Resource: "/data", SourceID: "source",
	}

	missing := validArtifact(claim)
	delete(missing.Graph.Nodes, claim.ID)
	if err := core.ValidateAirWithErrors(missing); err == nil {
		t.Fatal("claim missing from graph must fail validation")
	}

	stale := validArtifact(claim)
	forged := claim
	forged.Scope.Jurisdictions = []string{"US"}
	stale.Graph.Nodes[claim.ID] = forged
	if err := core.ValidateAirWithErrors(stale); err == nil {
		t.Fatal("stale graph-node copy must fail validation")
	}

	extra := validArtifact(claim)
	extra.Graph.Nodes["extra"] = core.Claim{
		ID: "extra", Type: core.Permission, Subject: "user", Action: "read",
		Resource: "/other", SourceID: "source",
	}
	if err := core.ValidateAirWithErrors(extra); err == nil {
		t.Fatal("extra graph node must fail validation")
	}
}

func TestDelegationsRequireExactlyOneSemanticParent(t *testing.T) {
	child := core.Claim{
		ID: "child", Type: core.Delegation, Subject: "service", Action: "read",
		Resource: "/data", SourceID: "source",
	}
	orphan := validArtifact(child)
	if err := core.ValidateAirWithErrors(orphan); err == nil {
		t.Fatal("orphan delegation must fail validation")
	}

	parentA := core.Claim{
		ID: "parent-a", Type: core.Permission, Subject: "admin", Action: "delegate",
		Resource: "/data", SourceID: "source",
	}
	parentB := parentA
	parentB.ID = "parent-b"
	multiple := validArtifact(parentA, parentB, child)
	multiple.Graph.Edges = []core.Edge{
		{FromID: parentA.ID, ToID: child.ID, EdgeType: core.Delegates},
		{FromID: parentB.ID, ToID: child.ID, EdgeType: core.Delegates},
	}
	if err := core.ValidateAirWithErrors(multiple); err == nil {
		t.Fatal("delegation with multiple parents must fail validation")
	}
}

func TestRuntimeEnforcesScopeAndConditions(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	claim := core.Claim{
		ID: "allow", Type: core.Permission, Subject: "user", Action: "read",
		Resource: "/data", SourceID: "source",
		Scope: core.Scope{
			Jurisdictions: []string{"US"},
			Operations:    []string{"read"},
			TimeStart:     &start,
			TimeEnd:       &end,
		},
		Conditions: map[string]interface{}{"mfa_required": true},
	}
	runtime := core.NewRuntimeInterface(validArtifact(claim))

	if runtime.IsAuthorized("user", "read", "/data")["allowed"].(bool) {
		t.Fatal("context-free query must deny scoped conditional permission")
	}
	validContext := core.AuthorizationContext{
		Jurisdiction: "US",
		At:           start.Add(30 * time.Minute),
		Attributes:   map[string]interface{}{"mfa_required": true},
	}
	if !runtime.IsAuthorizedWithContext("user", "read", "/data", validContext)["allowed"].(bool) {
		t.Fatal("matching scope and conditions should authorize")
	}
	wrongJurisdiction := validContext
	wrongJurisdiction.Jurisdiction = "CA"
	if runtime.IsAuthorizedWithContext("user", "read", "/data", wrongJurisdiction)["allowed"].(bool) {
		t.Fatal("wrong jurisdiction must deny")
	}
	expired := validContext
	expired.At = end.Add(time.Second)
	if runtime.IsAuthorizedWithContext("user", "read", "/data", expired)["allowed"].(bool) {
		t.Fatal("expired permission must deny")
	}
	missingCondition := validContext
	missingCondition.Attributes = nil
	if runtime.IsAuthorizedWithContext("user", "read", "/data", missingCondition)["allowed"].(bool) {
		t.Fatal("missing required condition must deny")
	}
}

func TestRuntimeUsesImmutableValidatedSnapshot(t *testing.T) {
	claim := core.Claim{
		ID: "deny", Type: core.Prohibition, Subject: "user", Action: "read",
		Resource: "/data", SourceID: "source",
		Scope: core.Scope{Jurisdictions: []string{"US"}},
	}
	artifact := validArtifact(claim)
	runtime := core.NewRuntimeInterface(artifact)

	artifact.Claims[0].Type = core.Permission
	artifact.Graph.Nodes[claim.ID] = artifact.Claims[0]
	copy := runtime.GetArtifact()
	copy.Claims[0].Type = core.Permission
	copy.Graph.Nodes[claim.ID] = copy.Claims[0]

	ctx := core.AuthorizationContext{Jurisdiction: "US", At: time.Now().UTC()}
	if runtime.IsAuthorizedWithContext("user", "read", "/data", ctx)["allowed"].(bool) {
		t.Fatal("external mutation must not change the runtime snapshot")
	}

	invalid := validArtifact(claim)
	invalid.Graph.Nodes = nil
	if core.NewRuntimeInterface(invalid).IsAuthorized("user", "read", "/data")["allowed"].(bool) {
		t.Fatal("invalid artifact must fail closed at runtime")
	}
}

func TestRuntimeRejectsBlankAuthorizationInputs(t *testing.T) {
	claim := core.Claim{
		ID: "wildcard", Type: core.Permission, Subject: "*", Action: "*",
		Resource: "*", SourceID: "source",
	}
	runtime := core.NewRuntimeInterface(validArtifact(claim))
	if runtime.IsAuthorized("", "", "")["allowed"].(bool) {
		t.Fatal("blank authorization inputs must fail closed")
	}
}

func TestScopedConflictsRemainApplicableAtRuntime(t *testing.T) {
	allow := baseClaim()
	allow["scope"] = map[string]interface{}{
		"jurisdictions": []interface{}{"EU", "US"},
	}
	deny := baseClaim()
	deny["id"] = "deny-us"
	deny["type"] = "prohibition"
	deny["scope"] = map[string]interface{}{
		"jurisdictions": []interface{}{"US"},
	}

	compiler := core.NewAuthorityCompiler()
	result := compiler.Process(sourceWithClaims("source", []interface{}{allow, deny}))
	success, ok := result.(core.CompilationSuccess)
	if !ok {
		t.Fatalf("expected scoped rules to compile, got %T", result)
	}
	if len(success.Artifact.Claims) != 2 {
		t.Fatalf("scoped rules must both survive resolution, got %d", len(success.Artifact.Claims))
	}
	runtime := core.NewRuntimeInterface(success.Artifact)
	if runtime.IsAuthorizedWithContext("user", "read", "/data", core.AuthorizationContext{Jurisdiction: "US"})["allowed"].(bool) {
		t.Fatal("US prohibition must deny")
	}
	if !runtime.IsAuthorizedWithContext("user", "read", "/data", core.AuthorizationContext{Jurisdiction: "EU"})["allowed"].(bool) {
		t.Fatal("EU permission must remain effective")
	}
}

func TestProofIsDeterministicAndCommitsPolicySemantics(t *testing.T) {
	source := sourceWithClaims("source", []interface{}{baseClaim()})
	first := core.NewAuthorityCompiler().Process(source).(core.CompilationSuccess)
	second := core.NewAuthorityCompiler().Process(source).(core.CompilationSuccess)
	if first.Proof != second.Proof {
		t.Fatal("identical authority input must produce deterministic proof output")
	}

	changedClaim := baseClaim()
	changedClaim["scope"] = map[string]interface{}{"jurisdictions": []interface{}{"US"}}
	changed := core.NewAuthorityCompiler().Process(
		sourceWithClaims("source", []interface{}{changedClaim}),
	).(core.CompilationSuccess)
	if first.Proof == changed.Proof {
		t.Fatal("scope changes must change the proof")
	}
}
