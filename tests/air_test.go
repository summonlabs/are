package tests

import (
	"testing"
	"time"

	"are/core"
)

func TestScopeCreation(t *testing.T) {
	scope := core.Scope{
		Jurisdictions: []string{"US", "EU"},
		TimeStart:     nil,
		TimeEnd:       nil,
		Operations:    []string{"read", "write"},
	}
	if len(scope.Jurisdictions) != 2 {
		t.Errorf("Expected 2 jurisdictions, got %d", len(scope.Jurisdictions))
	}
	if len(scope.Operations) != 2 {
		t.Errorf("Expected 2 operations, got %d", len(scope.Operations))
	}
}

func TestClaimCreation(t *testing.T) {
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
	if claim.ID != "claim_1" {
		t.Errorf("Expected ID 'claim_1', got '%s'", claim.ID)
	}
	if claim.Type != core.Permission {
		t.Errorf("Expected type Permission, got %v", claim.Type)
	}
}

func TestAuthoritySourceCreation(t *testing.T) {
	source := core.AuthoritySource{
		ID:          "source_1",
		Type:        core.Legal,
		Name:        "Privacy Law",
		Description: "Data protection regulations",
		Version:     "1.0",
		Metadata:    map[string]interface{}{},
	}
	if source.Type != core.Legal {
		t.Errorf("Expected type Legal, got %v", source.Type)
	}
	if source.Name != "Privacy Law" {
		t.Errorf("Expected name 'Privacy Law', got '%s'", source.Name)
	}
}

func TestAuthorityGraphCreation(t *testing.T) {
	graph := core.AuthorityGraph{
		Nodes: make(map[string]core.Claim),
		Edges: []core.Edge{},
	}
	if len(graph.Nodes) != 0 {
		t.Errorf("Expected 0 nodes, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 0 {
		t.Errorf("Expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestAuthorityArtifactCreation(t *testing.T) {
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
	if len(artifact.Claims) != 1 {
		t.Errorf("Expected 1 claim, got %d", len(artifact.Claims))
	}
}

func TestAuthorityTypeOrder(t *testing.T) {
	order := core.AuthorityTypeOrder()
	if order[core.Sovereign] >= order[core.Legal] {
		t.Error("Sovereign should have higher precedence than Legal")
	}
	if order[core.Legal] >= order[core.Regulatory] {
		t.Error("Legal should have higher precedence than Regulatory")
	}
	if order[core.Regulatory] >= order[core.Organizational] {
		t.Error("Regulatory should have higher precedence than Organizational")
	}
	if order[core.Organizational] >= order[core.Contractual] {
		t.Error("Organizational should have higher precedence than Contractual")
	}
}

func TestIsValidClaimType(t *testing.T) {
	validTypes := []core.ClaimType{core.Permission, core.Prohibition, core.Obligation, core.Delegation}
	for _, ct := range validTypes {
		if !core.IsValidClaimType(ct) {
			t.Errorf("Expected %v to be valid", ct)
		}
	}
	if core.IsValidClaimType("invalid") {
		t.Error("Invalid claim type should not be valid")
	}
}

func TestIsValidEdgeType(t *testing.T) {
	validTypes := []core.EdgeType{core.Delegates, core.Revokes, core.Supersedes}
	for _, et := range validTypes {
		if !core.IsValidEdgeType(et) {
			t.Errorf("Expected %v to be valid", et)
		}
	}
	if core.IsValidEdgeType("invalid") {
		t.Error("Invalid edge type should not be valid")
	}
}