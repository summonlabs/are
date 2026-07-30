package core

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// ValidateAir validates an authority artifact (legacy bool return).
// Deprecated: Use ValidateAirWithErrors for detailed error information.
func ValidateAir(artifact AuthorityArtifact) bool {
	return ValidateAirWithErrors(artifact) == nil
}

func ValidateAirWithErrors(artifact AuthorityArtifact) error {
	if artifact.ID == "" {
		return &ValidationError{
			Field:   "artifact.ID",
			Message: "artifact ID is required",
		}
	}
	if artifact.SourceID == "" {
		return &ValidationError{
			Field:   "artifact.SourceID",
			Message: "artifact source ID is required",
		}
	}
	if artifact.Graph.Nodes == nil {
		return ErrNilGraph
	}

	claimsByID := make(map[string]Claim, len(artifact.Claims))
	for _, claim := range artifact.Claims {
		if _, exists := claimsByID[claim.ID]; exists {
			return &ValidationError{
				Field:   "claim.ID",
				Message: fmt.Sprintf("duplicate claim ID: %s", claim.ID),
				Err:     ErrInvalidClaim,
			}
		}
		if err := validateClaimWithErrors(claim); err != nil {
			return err
		}
		claimsByID[claim.ID] = claim
	}

	nodeKeys := make([]string, 0, len(artifact.Graph.Nodes))
	for nodeKey := range artifact.Graph.Nodes {
		nodeKeys = append(nodeKeys, nodeKey)
	}
	sort.Strings(nodeKeys)
	for _, nodeKey := range nodeKeys {
		node := artifact.Graph.Nodes[nodeKey]
		if nodeKey != node.ID {
			return &ValidationError{
				Field:   "graph.Nodes",
				Message: fmt.Sprintf("node map key %q does not match node ID %q", nodeKey, node.ID),
				Err:     ErrInvalidClaim,
			}
		}
		if err := validateClaimWithErrors(node); err != nil {
			return &ValidationError{
				Field:   "graph.Nodes",
				Message: fmt.Sprintf("node %s failed validation", nodeKey),
				Err:     err,
			}
		}

		claim, exists := claimsByID[nodeKey]
		if !exists {
			return &ValidationError{
				Field:   "graph.Nodes",
				Message: fmt.Sprintf("graph contains node with no matching claim: %s", nodeKey),
				Err:     ErrInvalidClaim,
			}
		}
		if !reflect.DeepEqual(claim, node) {
			return &ValidationError{
				Field:   "graph.Nodes",
				Message: fmt.Sprintf("graph node does not match claim: %s", nodeKey),
				Err:     ErrInvalidClaim,
			}
		}
	}

	for _, claim := range artifact.Claims {
		if _, exists := artifact.Graph.Nodes[claim.ID]; !exists {
			return &ValidationError{
				Field:   "graph.Nodes",
				Message: fmt.Sprintf("claim is missing from graph: %s", claim.ID),
				Err:     ErrInvalidClaim,
			}
		}
	}

	if err := validateGraphWithErrors(artifact.Graph); err != nil {
		return err
	}

	return nil
}

func validateClaimWithErrors(claim Claim) error {
	if !validateClaim(claim) {
		return &ValidationError{
			Field:   "claim",
			Message: fmt.Sprintf("claim %s failed validation", claim.ID),
			Err:     ErrInvalidClaim,
		}
	}
	if _, err := json.Marshal(claim.Conditions); err != nil {
		return &ValidationError{
			Field:   "claim.Conditions",
			Message: fmt.Sprintf("claim %s conditions are not JSON-serializable", claim.ID),
			Err:     err,
		}
	}
	return nil
}

func validateClaim(claim Claim) bool {
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
	if !IsValidClaimType(claim.Type) {
		return false
	}
	if !ValidateScope(claim.Scope) {
		return false
	}

	return true
}

func isScopeContained(inner Scope, outer Scope) bool {
	if !isStringSetContained(inner.Jurisdictions, outer.Jurisdictions) {
		return false
	}

	if !isStringSetContained(inner.Operations, outer.Operations) {
		return false
	}

	// Time bounds must be within outer bounds
	if outer.TimeStart != nil {
		if inner.TimeStart == nil {
			return false
		}
		if inner.TimeStart.Before(*outer.TimeStart) {
			return false
		}
	}
	if outer.TimeEnd != nil {
		if inner.TimeEnd == nil {
			return false
		}
		if inner.TimeEnd.After(*outer.TimeEnd) {
			return false
		}
	}

	return true
}

func isStringSetContained(inner []string, outer []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}

	outerSet := make(map[string]bool)
	for _, value := range outer {
		outerSet[value] = true
	}
	for _, value := range inner {
		if !outerSet[value] {
			return false
		}
	}
	return true
}

func validateGraph(graph AuthorityGraph) bool {
	return validateGraphWithErrors(graph) == nil
}

// validateGraphWithErrors validates graph structure with detailed errors.
func validateGraphWithErrors(graph AuthorityGraph) error {
	if graph.Nodes == nil {
		return ErrNilGraph
	}

	seenEdges := make(map[Edge]struct{}, len(graph.Edges))
	incomingDelegations := make(map[string]int)
	for _, edge := range graph.Edges {
		if _, duplicate := seenEdges[edge]; duplicate {
			return &ValidationError{
				Field:   "graph.Edges",
				Message: fmt.Sprintf("duplicate edge: %s -> %s (%s)", edge.FromID, edge.ToID, edge.EdgeType),
			}
		}
		seenEdges[edge] = struct{}{}

		from, fromExists := graph.Nodes[edge.FromID]
		if !fromExists {
			return &ValidationError{
				Field:   "edge.FromID",
				Message: fmt.Sprintf("edge references non-existent node: %s", edge.FromID),
				Err:     ErrInvalidEdgeReference,
			}
		}
		to, toExists := graph.Nodes[edge.ToID]
		if !toExists {
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
		if !IsValidEdgeType(edge.EdgeType) {
			return &ValidationError{
				Field:   "edge.EdgeType",
				Message: fmt.Sprintf("invalid edge type: %s", edge.EdgeType),
			}
		}

		if edge.EdgeType == Delegates {
			if from.Action != "delegate" {
				return &ValidationError{
					Field:   "edge.FromID",
					Message: fmt.Sprintf("delegation source claim %s must have action %q", from.ID, "delegate"),
					Err:     ErrInvalidClaim,
				}
			}
			if to.Type != Delegation {
				return &ValidationError{
					Field:   "edge.ToID",
					Message: fmt.Sprintf("delegation edge target %s must be a delegation claim", to.ID),
					Err:     ErrInvalidClaim,
				}
			}
			incomingDelegations[to.ID]++
			if !isScopeContained(to.Scope, from.Scope) {
				return &ValidationError{
					Field:   "claim.Scope",
					Message: fmt.Sprintf("delegation claim %s exceeds parent claim %s scope", to.ID, from.ID),
					Err:     ErrDelegationScopeViolation,
				}
			}
		}
	}

	nodeIDs := make([]string, 0, len(graph.Nodes))
	for nodeID := range graph.Nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	for _, nodeID := range nodeIDs {
		node := graph.Nodes[nodeID]
		if node.Type != Delegation {
			continue
		}
		switch incomingDelegations[nodeID] {
		case 0:
			return &ValidationError{
				Field:   "graph.Edges",
				Message: fmt.Sprintf("delegation claim has no parent: %s", nodeID),
				Err:     ErrInvalidClaim,
			}
		case 1:
			// Exactly one real parent is required.
		default:
			return &ValidationError{
				Field:   "graph.Edges",
				Message: fmt.Sprintf("delegation claim has multiple parents: %s", nodeID),
				Err:     ErrInvalidClaim,
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
