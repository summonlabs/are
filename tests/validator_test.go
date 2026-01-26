package tests

import (
	"testing"
	"time"

	"are/core"
)

func TestValidateAir(t *testing.T) {
	scope := core.Scope{
		Jurisdictions: []string{"US"},
		TimeStart:     nil,
		TimeEnd:       nil,
		Operations:    []string{"read"},
	}
	claim := core.Claim{
		ID:         "claim_1",
		Type:       core.Permission,
		Subject:    "user_1",
		Action:     "read",
		Resource:   "/data/file.txt",
		Scope:      scope,
		Conditions: nil,
		SourceID:   "source_1",
	}
	artifact := core.AuthorityArtifact{
		ID:          "test_artifact",
		SourceID:    "source_1",
		Claims:      []core.Claim{claim},
		Graph:       core.AuthorityGraph{Nodes: make(map[string]core.Claim), Edges: []core.Edge{}},
		GeneratedAt: time.Now().UTC(),
	}

	if !core.ValidateAir(artifact) {
		t.Error("Expected validation to pass")
	}
}

func TestValidateScope(t *testing.T) {
	scope := core.Scope{
		Jurisdictions: []string{"US"},
		TimeStart:     nil,
		TimeEnd:       nil,
		Operations:    []string{"read"},
	}
	if !core.ValidateScope(scope) {
		t.Error("Expected scope validation to pass")
	}
}

func TestValidateAirWithNoneGraph(t *testing.T) {
	scope := core.Scope{
		Jurisdictions: []string{"US"},
		TimeStart:     nil,
		TimeEnd:       nil,
		Operations:    []string{"read"},
	}
	claim := core.Claim{
		ID:         "claim_1",
		Type:       core.Permission,
		Subject:    "user_1",
		Action:     "read",
		Resource:   "/data/file.txt",
		Scope:      scope,
		Conditions: nil,
		SourceID:   "source_1",
	}
	artifact := core.AuthorityArtifact{
		ID:          "test_artifact",
		SourceID:    "source_1",
		Claims:      []core.Claim{claim},
		Graph:       core.AuthorityGraph{}, // This should fail validation
		GeneratedAt: time.Now().UTC(),
	}

	if core.ValidateAir(artifact) {
		t.Error("Expected validation to fail with nil graph")
	}
}


func TestValidateAirWithErrors(t *testing.T) {
	// Test empty artifact with initialized graph (should pass)
	emptyArtifact := core.AuthorityArtifact{
		ID:          "empty",
		SourceID:    "source",
		Claims:      []core.Claim{},
		Graph:       core.AuthorityGraph{Nodes: make(map[string]core.Claim), Edges: []core.Edge{}},
		GeneratedAt: time.Now().UTC(),
	}
	if err := core.ValidateAirWithErrors(emptyArtifact); err != nil {
		t.Errorf("Empty artifact with initialized graph should be valid: %v", err)
	}

	// Test nil graph (should fail)
	nilGraphArtifact := core.AuthorityArtifact{
		ID:          "nil_graph",
		SourceID:    "source",
		Claims:      []core.Claim{},
		Graph:       core.AuthorityGraph{}, // Nodes is nil
		GeneratedAt: time.Now().UTC(),
	}
	if err := core.ValidateAirWithErrors(nilGraphArtifact); err == nil {
		t.Error("Artifact with nil graph nodes should fail validation")
	}
}

func TestValidateScopeWithErrors(t *testing.T) {
	// Valid scope with proper time bounds
	start := time.Now()
	end := start.Add(time.Hour)
	validScope := core.Scope{
		Jurisdictions: []string{"US"},
		TimeStart:     &start,
		TimeEnd:       &end,
		Operations:    []string{"read"},
	}
	if err := core.ValidateScopeWithErrors(validScope); err != nil {
		t.Errorf("Valid scope should pass: %v", err)
	}

	// Invalid scope (end before start)
	invalidScope := core.Scope{
		TimeStart: &end,
		TimeEnd:   &start,
	}
	if err := core.ValidateScopeWithErrors(invalidScope); err == nil {
		t.Error("Scope with end before start should fail validation")
	}
}

func TestCyclicGraphDetection(t *testing.T) {
	// Create a cyclic graph
	graph := core.AuthorityGraph{
		Nodes: map[string]core.Claim{
			"a": {ID: "a", Type: core.Permission, Subject: "u", Action: "r", Resource: "/", SourceID: "s"},
			"b": {ID: "b", Type: core.Permission, Subject: "u", Action: "r", Resource: "/", SourceID: "s"},
		},
		Edges: []core.Edge{
			{FromID: "a", ToID: "b", EdgeType: core.Delegates},
			{FromID: "b", ToID: "a", EdgeType: core.Delegates},
		},
	}

	artifact := core.AuthorityArtifact{
		ID:          "cyclic",
		SourceID:    "source",
		Claims:      []core.Claim{graph.Nodes["a"], graph.Nodes["b"]},
		Graph:       graph,
		GeneratedAt: time.Now().UTC(),
	}

	err := core.ValidateAirWithErrors(artifact)
	if err == nil {
		t.Error("Cyclic graph should fail validation")
	}
}