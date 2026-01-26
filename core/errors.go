// Package core provides the Authority Realization Engine implementation.
package core

import (
	"errors"
	"fmt"
)

// Sentinel errors for ARE operations.
var (
	// ErrNilArtifact indicates an operation received a nil artifact.
	ErrNilArtifact = errors.New("artifact is nil")

	// ErrNilSource indicates an operation received a nil source.
	ErrNilSource = errors.New("source is nil")

	// ErrEmptySourceID indicates a source has an empty ID.
	ErrEmptySourceID = errors.New("source ID is empty")

	// ErrInvalidClaim indicates a claim failed validation.
	ErrInvalidClaim = errors.New("invalid claim")

	// ErrCyclicGraph indicates the authority graph contains cycles.
	ErrCyclicGraph = errors.New("authority graph contains cycles")

	// ErrNilGraph indicates the graph is nil when required.
	ErrNilGraph = errors.New("graph nodes map is nil")

	// ErrUnresolvableConflict indicates conflicts could not be resolved.
	ErrUnresolvableConflict = errors.New("unresolvable authority conflict")

	// ErrInvalidScope indicates a scope failed validation.
	ErrInvalidScope = errors.New("invalid scope")

	// ErrDelegationScopeViolation indicates delegation exceeds delegator scope.
	ErrDelegationScopeViolation = errors.New("delegation scope exceeds delegator scope")

	// ErrInvalidEdgeReference indicates an edge references non-existent node.
	ErrInvalidEdgeReference = errors.New("edge references non-existent node")

	// ErrInvalidVersion indicates a version string is malformed.
	ErrInvalidVersion = errors.New("invalid version string")
)

// ValidationError provides detailed validation failure information.
type ValidationError struct {
	Field   string
	Message string
	Err     error
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("validation error on %s: %s: %v", e.Field, e.Message, e.Err)
	}
	return fmt.Sprintf("validation error on %s: %s", e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// CompilationError provides detailed compilation failure information.
type CompilationError struct {
	Stage            string
	Message          string
	InvolvedClaimIDs []string
	Err              error
}

func (e *CompilationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("compilation error at %s: %s: %v", e.Stage, e.Message, e.Err)
	}
	return fmt.Sprintf("compilation error at %s: %s", e.Stage, e.Message)
}

func (e *CompilationError) Unwrap() error {
	return e.Err
}

// ConflictError provides detailed conflict resolution failure information.
type ConflictError struct {
	ClaimIDs []string
	Message  string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict resolution failed for claims %v: %s", e.ClaimIDs, e.Message)
}

// newValidationError creates a new ValidationError.
func newValidationError(field, message string, err error) *ValidationError {
	return &ValidationError{Field: field, Message: message, Err: err}
}