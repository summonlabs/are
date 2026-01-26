package core

import (
	"fmt"
	"sort"
)

// ValidateAir validates an authority artifact (legacy bool return).
// Deprecated: Use ValidateAirWithErrors for detailed error information.
func ValidateAir(artifact AuthorityArtifact) bool {
	return ValidateAirWithErrors(artifact) == nil
}

func ValidateAirWithErrors(artifact AuthorityArtifact) error {
	// Validate graph is initialized
	if artifact.Graph.Nodes == nil {
		return ErrNilGraph
	}

	// Empty artifacts with initialized graph are valid
	if len(artifact.Claims) == 0 && len(artifact.Graph.Nodes) == 0 {
		return nil
	}

	for _, claim := range artifact.Claims {
		if err := validateClaimWithErrors(claim, artifact.Graph); err != nil {
			return err
		}
	}

	if err := validateGraphWithErrors(artifact.Graph); err != nil {
		return err
	}

	return nil
}

func validateClaimWithErrors(claim Claim, graph AuthorityGraph) error {
	if !validateClaim(claim, graph) {
		return &ValidationError{
			Field:   "claim",
			Message: fmt.Sprintf("claim %s failed validation", claim.ID),
		}
	}
	return nil
}

func validateClaim(claim Claim, graph AuthorityGraph) bool {
	if claim.ID == "" {
		return false
	}
	if claim.Subject == "" {
		return false
	}
	if claim.Action == "" {
		return false
	}
	if claim.Resource == "" {
		return false
	}
	if claim.SourceID == "" {
		return false
	}

	// Validate delegation claims
	if claim.Type == Delegation {
		if !validateDelegationClaim(claim, graph) {
			return false
		}
	}

	return true
}

func validateDelegationClaim(claim Claim, graph AuthorityGraph) bool {
	// Find delegator (parent in graph)
	delegatorClaim := Claim{}
	for _, edge := range graph.Edges {
		if edge.ToID == claim.ID && edge.EdgeType == Delegates {
			delegatorClaim = graph.Nodes[edge.FromID]
			break
		}
	}

	if delegatorClaim.ID != "" {
		// Delegation must be scope-contained within delegator's scope
		if !isScopeContained(claim.Scope, delegatorClaim.Scope) {
			return false
		}
	}

	return true
}

func isScopeContained(inner Scope, outer Scope) bool {
	// Jurisdictions must be subset
	innerSet := make(map[string]bool)
	for _, j := range inner.Jurisdictions {
		innerSet[j] = true
	}
	outerSet := make(map[string]bool)
	for _, j := range outer.Jurisdictions {
		outerSet[j] = true
	}
	for j := range innerSet {
		if !outerSet[j] {
			return false
		}
	}

	// Operations must be subset
	innerOpSet := make(map[string]bool)
	for _, o := range inner.Operations {
		innerOpSet[o] = true
	}
	outerOpSet := make(map[string]bool)
	for _, o := range outer.Operations {
		outerOpSet[o] = true
	}
	for o := range innerOpSet {
		if !outerOpSet[o] {
			return false
		}
	}

	// Time bounds must be within outer bounds
	if outer.TimeStart != nil && inner.TimeStart != nil {
		if inner.TimeStart.Before(*outer.TimeStart) {
			return false
		}
	}
	if outer.TimeEnd != nil && inner.TimeEnd != nil {
		if inner.TimeEnd.After(*outer.TimeEnd) {
			return false
		}
	}

	return true
}

func validateGraph(graph AuthorityGraph) bool {
	// No cyclic delegation chains
	// All authority graphs must be acyclic
	// Every claim references exactly one authority source
	// No delegation claims may delegate beyond their own scope

	// Validate that graph is not nil (required for v1.0.0)
	if graph.Nodes == nil {
		return false
	}

	// Validate node IDs match edge references
	nodeIDs := make(map[string]bool)
	for id := range graph.Nodes {
		nodeIDs[id] = true
	}
	for _, edge := range graph.Edges {
		if !nodeIDs[edge.FromID] {
			return false
		}
		if !nodeIDs[edge.ToID] {
			return false
		}
		if edge.EdgeType == "" {
			return false
		}
	}

	// Validate acyclic property (delegation chains)
	if hasCycles(graph) {
		return false
	}

	return true
}

// validateGraphWithErrors validates graph structure with detailed errors.
func validateGraphWithErrors(graph AuthorityGraph) error {
	if graph.Nodes == nil {
		return ErrNilGraph
	}

	// Validate node IDs match edge references
	nodeIDs := make(map[string]bool)
	for id := range graph.Nodes {
		nodeIDs[id] = true
	}
	for _, edge := range graph.Edges {
		if !nodeIDs[edge.FromID] {
			return &ValidationError{
				Field:   "edge.FromID",
				Message: fmt.Sprintf("edge references non-existent node: %s", edge.FromID),
				Err:     ErrInvalidEdgeReference,
			}
		}
		if !nodeIDs[edge.ToID] {
			return &ValidationError{
				Field:   "edge.ToID",
				Message: fmt.Sprintf("edge references non-existent node: %s", edge.ToID),
				Err:     ErrInvalidEdgeReference,
			}
		}
		if edge.EdgeType == "" {
			return &ValidationError{
				Field:   "edge.EdgeType",
				Message: "edge type is required",
			}
		}
	}

	if hasCycles(graph) {
		return ErrCyclicGraph
	}

	return nil
}

func hasCycles(graph AuthorityGraph) bool {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var visit func(nodeID string) bool
	visit = func(nodeID string) bool {
		visited[nodeID] = true
		recStack[nodeID] = true

		for _, edge := range graph.Edges {
			if edge.FromID == nodeID {
				neighbor := edge.ToID
				if !visited[neighbor] {
					if visit(neighbor) {
						return true
					}
				} else if recStack[neighbor] {
					return true
				}
			}
		}

		delete(recStack, nodeID)
		return false
	}

	// Sort node IDs for deterministic traversal
	nodeIDs := make([]string, 0, len(graph.Nodes))
	for nodeID := range graph.Nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)

	for _, nodeID := range nodeIDs {
		if !visited[nodeID] {
			if visit(nodeID) {
				return true
			}
		}
	}
	return false
}

// ValidateScope validates a scope.
func ValidateScope(scope Scope) bool {
	// Empty sets are valid (treated as universal scope)
	// This is a design decision - document it in README

	// Validate temporal bounds
	if scope.TimeStart != nil && scope.TimeEnd != nil {
		if scope.TimeStart.After(*scope.TimeEnd) {
			return false
		}
	}

	return true
}

// ValidateScopeWithErrors validates a scope with detailed errors.
func ValidateScopeWithErrors(scope Scope) error {
	if scope.TimeStart != nil && scope.TimeEnd != nil {
		if scope.TimeStart.After(*scope.TimeEnd) {
			return &ValidationError{
				Field:   "scope.Time",
				Message: "time_start must be before time_end",
				Err:     ErrInvalidScope,
			}
		}
	}
	return nil
}