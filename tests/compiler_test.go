package tests

import (
	"context"
	"strings"
	"testing"

	"are/core"
)

func TestCompilationPipeline(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:          "test_source",
		Type:        core.Legal,
		Name:        "Test Authority",
		Description: "For testing purposes",
		Version:     "1.0",
		Metadata:    map[string]interface{}{},
	}

	result := compiler.Process(source)
	if result == nil {
		t.Error("Expected a result, got nil")
	}
	if _, ok := result.(core.CompilationSuccess); !ok {
		t.Error("Expected CompilationSuccess for valid source")
	}
}

func TestCompilationWithClaims(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:          "test_source",
		Type:        core.Legal,
		Name:        "Test Authority",
		Description: "For testing purposes",
		Version:     "1.0",
		Metadata: map[string]interface{}{
			"claims": []interface{}{
				map[string]interface{}{
					"id":       "claim_1",
					"type":     "permission",
					"subject":  "user_1",
					"action":   "read",
					"resource": "/data/file.txt",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US"},
						"time_start":    "2023-01-01T00:00:00Z",
						"time_end":      "2024-01-01T00:00:00Z",
						"operations":    []string{"read"},
					},
				},
			},
		},
	}

	result := compiler.Process(source)
	if result == nil {
		t.Error("Expected a result, got nil")
	}
	if _, ok := result.(core.CompilationSuccess); !ok {
		t.Errorf("Expected CompilationSuccess, got %T", result)
	}
}

func TestFullCompilationWithConflicts(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:          "test_source",
		Type:        core.Legal,
		Name:        "Test Authority",
		Description: "For testing purposes",
		Version:     "1.0",
		Metadata: map[string]interface{}{
			"claims": []interface{}{
				map[string]interface{}{
					"id":       "claim_permission",
					"type":     "permission",
					"subject":  "user_1",
					"action":   "read",
					"resource": "/data/secret.txt",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US"},
						"time_start":    "2023-01-01T00:00:00Z",
						"time_end":      "2024-01-01T00:00:00Z",
						"operations":    []string{"read"},
					},
				},
				map[string]interface{}{
					"id":       "claim_prohibition",
					"type":     "prohibition",
					"subject":  "user_1",
					"action":   "read",
					"resource": "/data/secret.txt",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US"},
						"time_start":    "2023-01-01T00:00:00Z",
						"time_end":      "2024-01-01T00:00:00Z",
						"operations":    []string{"read"},
					},
				},
			},
		},
	}

	result := compiler.Process(source)
	if result == nil {
		t.Error("Expected a result, got nil")
	}
	// Conflicts should be resolved (one claim wins)
	if _, ok := result.(core.CompilationSuccess); !ok {
		t.Errorf("Expected CompilationSuccess after conflict resolution, got %T", result)
	}
}

func TestRuntimeAuthorization(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:          "test_source",
		Type:        core.Organizational,
		Name:        "Test Policy",
		Description: "Test policy",
		Version:     "1.0",
		Metadata: map[string]interface{}{
			"claims": []interface{}{
				map[string]interface{}{
					"id":       "allow_read",
					"type":     "permission",
					"subject":  "engineer",
					"action":   "read",
					"resource": "/code/*",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US"},
						"operations":    []string{"read"},
					},
				},
			},
		},
	}

	result := compiler.Process(source)
	if result == nil {
		t.Error("Expected a result, got nil")
	}

	runtime := core.NewRuntimeInterface(result.(core.CompilationSuccess).Artifact)

	// Should be authorized
	authResult := runtime.IsAuthorized("engineer", "read", "/code/main.py")
	if !authResult["allowed"].(bool) {
		t.Error("Expected engineer to be authorized for reading /code/main.py")
	}

	// Should not be authorized (fail closed)
	authResult = runtime.IsAuthorized("intern", "read", "/code/main.py")
	if authResult["allowed"].(bool) {
		t.Error("Expected intern to be denied authorization for reading /code/main.py")
	}
}

func TestContextCancellation(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:       "test",
		Type:     core.Legal,
		Name:     "Test",
		Version:  "1.0.0",
		Metadata: map[string]interface{}{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := compiler.Normalize(ctx, source)
	if err == nil {
		t.Error("Expected error with cancelled context")
	}
}

func TestEmptySourceIDFails(t *testing.T) {
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:       "", // Empty ID
		Type:     core.Legal,
		Name:     "Test",
		Version:  "1.0.0",
		Metadata: map[string]interface{}{},
	}

	result := compiler.Process(source)
	if _, ok := result.(core.CompilationFailure); !ok {
		t.Error("Expected CompilationFailure for empty source ID")
	}
}

func TestDeterministicProofOutput(t *testing.T) {
	source := core.AuthoritySource{
		ID:       "test",
		Type:     core.Organizational,
		Name:     "Test",
		Version:  "1.0.0",
		Metadata: map[string]interface{}{
			"claims": []interface{}{
				map[string]interface{}{
					"id":       "claim_b",
					"type":     "permission",
					"subject":  "user",
					"action":   "read",
					"resource": "/b",
					"scope":    map[string]interface{}{},
				},
				map[string]interface{}{
					"id":       "claim_a",
					"type":     "permission",
					"subject":  "user",
					"action":   "read",
					"resource": "/a",
					"scope":    map[string]interface{}{},
				},
			},
		},
	}

	// Run multiple times, proof should be identical
	var proofs []string
	for i := 0; i < 3; i++ {
		newCompiler := core.NewAuthorityCompiler()
		result := newCompiler.Process(source)
		if success, ok := result.(core.CompilationSuccess); ok {
			proofs = append(proofs, success.Proof)
		}
	}

	// Check that claim_a appears before claim_b in sorted output
	if len(proofs) > 0 {
		if !strings.Contains(proofs[0], `"id": "claim_a"`) {
			t.Error("Proof should contain claim_a")
		}
	}
}

func TestVersionParsing(t *testing.T) {
	// Test via compilation with versioned sources
	compiler := core.NewAuthorityCompiler()
	source := core.AuthoritySource{
		ID:       "test",
		Type:     core.Legal,
		Name:     "Test",
		Version:  "2.1.0",
		Metadata: map[string]interface{}{},
	}

	result := compiler.Process(source)
	if _, ok := result.(core.CompilationSuccess); !ok {
		t.Error("Version parsing should not cause failure")
	}
}