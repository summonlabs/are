package core

import (
	"strings"
	"sync"
	"time"
)

// AuthorizationResult represents the result of an authorization query.
type AuthorizationResult struct {
	Allowed     bool                   `json:"allowed"`
	AuthorityID string                 `json:"authority_id"`
	Reason      string                 `json:"reason"`
	Scope       map[string]interface{} `json:"scope"`
}

// RuntimeInterface defines how runtime systems query ARE for authorization decisions.
// Thread-safe for concurrent authorization queries.
// Note: RuntimeInterface responses are advisory reflections of compiled authority.
// Runtime systems MUST enforce constraints independently.
type RuntimeInterface struct {
	artifact AuthorityArtifact
	mu       sync.RWMutex
}

// NewRuntimeInterface creates a new thread-safe instance of RuntimeInterface.
func NewRuntimeInterface(artifact AuthorityArtifact) *RuntimeInterface {
	return &RuntimeInterface{
		artifact: artifact,
	}
}

// IsAuthorized checks if an action is authorized under the given authority.
// Thread-safe for concurrent access.
func (ri *RuntimeInterface) IsAuthorized(subject, action, resource string) map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	// Find applicable claims (with wildcard matching)
	applicable := []Claim{}
	for _, claim := range ri.artifact.Claims {
		if ri.matches(claim.Subject, subject) &&
			ri.matches(claim.Action, action) &&
			ri.matches(claim.Resource, resource) {
			applicable = append(applicable, claim)
		}
	}

	// Check for prohibitions first (highest priority)
	for _, claim := range applicable {
		if claim.Type == Prohibition {
			return map[string]interface{}{
				"allowed":   false,
				"authority_id": claim.ID,
				"reason":    "Prohibited by authority",
				"scope":     ri.scopeToDict(claim.Scope),
			}
		}
	}

	// Check for permissions
	for _, claim := range applicable {
		if claim.Type == Permission {
			return map[string]interface{}{
				"allowed":   true,
				"authority_id": claim.ID,
				"reason":    "Permitted by authority",
				"scope":     ri.scopeToDict(claim.Scope),
			}
		}
	}

	// Fail closed
	return map[string]interface{}{
		"allowed":   false,
		"authority_id": ri.artifact.ID,
		"reason":    "No applicable authority found - failing closed",
		"scope":     map[string]interface{}{},
	}
}

// GetObligations gets all obligations that apply to this context.
// Thread-safe for concurrent access.
func (ri *RuntimeInterface) GetObligations(subject, action, resource string) []map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	obligations := []map[string]interface{}{}
	for _, claim := range ri.artifact.Claims {
		if claim.Type == Obligation {
			if ri.matches(claim.Subject, subject) &&
				ri.matches(claim.Action, action) &&
				ri.matches(claim.Resource, resource) {
				obligations = append(obligations, map[string]interface{}{
					"claim_id":   claim.ID,
					"action":     claim.Action,
					"scope":      ri.scopeToDict(claim.Scope),
					"conditions": claim.Conditions,
				})
			}
		}
	}
	return obligations
}

// GetAuthorityInfo returns detailed information about which authority applies.
// Thread-safe for concurrent access.
func (ri *RuntimeInterface) GetAuthorityInfo(subject, action, resource string) map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	applicable := []Claim{}
	for _, claim := range ri.artifact.Claims {
		if ri.matches(claim.Subject, subject) &&
			ri.matches(claim.Action, action) &&
			ri.matches(claim.Resource, resource) {
			applicable = append(applicable, claim)
		}
	}

	applicableClaims := []map[string]interface{}{}
	for _, claim := range applicable {
		applicableClaims = append(applicableClaims, map[string]interface{}{
			"id":         claim.ID,
			"type":       claim.Type,
			"scope":      ri.scopeToDict(claim.Scope),
			"conditions": claim.Conditions,
		})
	}

	return map[string]interface{}{
		"artifact_id":     ri.artifact.ID,
		"applicable_claims": applicableClaims,
		"total_claims":    len(ri.artifact.Claims),
	}
}

func (ri *RuntimeInterface) matches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == value {
		return true
	}

	// Handle wildcard patterns like "/code/*"
	if strings.Contains(pattern, "*") {
		// Convert pattern to regex-like matching
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(value, prefix+"/") {
				return true
			}
		} else if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}

	return false
}

func (ri *RuntimeInterface) scopeToDict(scope Scope) map[string]interface{} {
	var timeStart, timeEnd interface{}
	if scope.TimeStart != nil {
		timeStart = scope.TimeStart.Format(time.RFC3339)
	}
	if scope.TimeEnd != nil {
		timeEnd = scope.TimeEnd.Format(time.RFC3339)
	}

	return map[string]interface{}{
		"jurisdictions": scope.Jurisdictions,
		"time_start":    timeStart,
		"time_end":      timeEnd,
		"operations":    scope.Operations,
	}
}

// GetArtifact returns a copy of the underlying artifact (thread-safe).
func (ri *RuntimeInterface) GetArtifact() AuthorityArtifact {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return ri.artifact
}