package main

import (
	"context"
	"fmt"
	"log"

	"are/core"
)

func main() {
	compiler := core.NewAuthorityCompiler()
	ctx := context.Background()
	_ = ctx // Available for cancellation if needed

	source := core.AuthoritySource{
		ID:          "company_policy",
		Type:        core.Organizational,
		Name:        "Engineering Access Policy",
		Description: "Access rules for engineering team",
		Version:     "2.1.0",
		Metadata: map[string]interface{}{
			"claims": []interface{}{
				map[string]interface{}{
					"id":       "eng_read",
					"type":     "permission",
					"subject":  "engineer",
					"action":   "read",
					"resource": "/repos/*",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US", "EU"},
						"operations":    []string{"read", "clone"},
					},
				},
				map[string]interface{}{
					"id":       "eng_write",
					"type":     "permission",
					"subject":  "engineer",
					"action":   "write",
					"resource": "/repos/*",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US", "EU"},
						"operations":    []string{"push"},
					},
				},
				map[string]interface{}{
					"id":       "intern_prohibition",
					"type":     "prohibition",
					"subject":  "intern",
					"action":   "write",
					"resource": "/repos/*",
					"scope": map[string]interface{}{
						"jurisdictions": []string{"US", "EU"},
						"operations":    []string{"push"},
					},
				},
			},
		},
	}

	result := compiler.Process(source)

	if success, ok := result.(core.CompilationSuccess); ok {
		fmt.Printf("✓ Compilation successful!\n")
		fmt.Printf("  Artifact ID: %s\n", success.Artifact.ID)
		fmt.Printf("  Claims: %d\n", len(success.Artifact.Claims))
		fmt.Printf("\nProof:\n%s\n", success.Proof)

		// Test runtime enforcement
		runtime := core.NewRuntimeInterface(success.Artifact)

		// Engineer should be able to read
		authResult := runtime.IsAuthorized("engineer", "read", "/repos/main.py")
		fmt.Printf("\nEngineer reading /repos/main.py: %s\n", map[bool]string{true: "ALLOWED", false: "DENIED"}[authResult["allowed"].(bool)])

		// Intern should not be able to write
		authResult = runtime.IsAuthorized("intern", "write", "/repos/main.py")
		fmt.Printf("Intern writing /repos/main.py: %s\n", map[bool]string{true: "ALLOWED", false: "DENIED"}[authResult["allowed"].(bool)])

		// Unknown subject should fail closed
		authResult = runtime.IsAuthorized("unknown", "read", "/repos/main.py")
		fmt.Printf("Unknown subject reading /repos/main.py: %s (fail-closed)\n", map[bool]string{true: "ALLOWED", false: "DENIED"}[authResult["allowed"].(bool)])

	} else if failure, ok := result.(core.CompilationFailure); ok {
		log.Fatalf("✗ Compilation failed at stage '%s': %s", failure.FailureStage, failure.ViolatedInvariant)
	}
}