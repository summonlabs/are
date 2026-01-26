// Package core provides the Authority Realization Engine implementation.
package core

import (
	"sync"
	"time"
)

// AuthorityType represents types of authority sources.
// Authority types follow strict precedence: sovereign > legal > regulatory > organizational > contractual.
type AuthorityType string

const (
	Sovereign     AuthorityType = "sovereign"
	Legal         AuthorityType = "legal"
	Regulatory    AuthorityType = "regulatory"
	Organizational AuthorityType = "organizational"
	Contractual   AuthorityType = "contractual"
)

// ClaimType represents semantic types of authority claims.
// Claims are mutually exclusive semantic operators that define authority relationships.
type ClaimType string

const (
	Permission  ClaimType = "permission"
	Prohibition ClaimType = "prohibition"
	Obligation  ClaimType = "obligation"
	Delegation  ClaimType = "delegation"
)

// EdgeType represents types of edges in the Authority Graph.
// Edges encode relationships between claims for precedence and conflict resolution.
type EdgeType string

const (
	Delegates EdgeType = "delegates"
	Revokes   EdgeType = "revokes"
	Supersedes EdgeType = "supersedes"
)

// Scope represents the jurisdictional, temporal, and operational boundaries of authority.
// Empty sets are treated as universal scope (applies everywhere/always/to all operations).
// This is an intentional design decision for fail-open scope semantics.
type Scope struct {
	Jurisdictions []string
	TimeStart     *time.Time // ISO format date-time
	TimeEnd       *time.Time // ISO format date-time
	Operations    []string
}

// Claim represents a single authority claim (permission, prohibition, obligation, delegation).
// Claims are immutable once created; modifications require creating new claims.
// Thread-safe for concurrent read access; write operations require external synchronization.
type Claim struct {
	ID         string
	Type       ClaimType
	Subject    string // e.g., role, user, system
	Action     string // e.g., read, write, execute
	Resource   string // e.g., file path, API endpoint
	Scope      Scope
	Conditions map[string]interface{}
	SourceID   string // Reference to AuthoritySource
}

// AuthoritySource represents the origin of authority.
// Sources are immutable reference objects that define the legitimacy basis for claims.
type AuthoritySource struct {
	ID          string
	Type        AuthorityType
	Name        string
	Description string
	Version     string
	Metadata    map[string]interface{}
}

// AuthorityGraph represents formal structure encoding precedence, inheritance, delegation, and revocation.
// Graphs must be acyclic; cyclic graphs fail validation.
// Thread-safe for concurrent read access when protected by parent artifact's mutex.
type AuthorityGraph struct {
	Nodes map[string]Claim
	Edges []Edge
}

// Edge represents a relationship between claims in the graph.
// Edges are directional: FromID -> ToID with semantic meaning defined by EdgeType.
// - Delegates: FromID delegates authority to ToID
// - Revokes: FromID revokes ToID
// - Supersedes: FromID supersedes ToID
type Edge struct {
	FromID   string
	ToID     string
	EdgeType EdgeType
}

// AuthorityArtifact represents compiled output that binds systems to authority.
// Artifacts are the primary output of the compilation pipeline.
// Thread-safe for concurrent read access; use RLock/RUnlock for reads.
type AuthorityArtifact struct {
	ID          string         `json:"id"`
	SourceID    string         `json:"source_id"`
	Claims      []Claim        `json:"claims"`
	Graph       AuthorityGraph `json:"graph"` // Always required, even if empty
	GeneratedAt time.Time      `json:"generated_at"`

	// mu protects concurrent access to artifact fields.
	// Use RLock for reads, Lock for writes.
	mu sync.RWMutex
}

// CompilationSuccess represents successful compilation outcome.
type CompilationSuccess struct {
	Artifact AuthorityArtifact
	Proof    string
}

// CompilationFailure represents failed compilation outcome.
type CompilationFailure struct {
	FailureStage     string   // ingestion, validation, resolution, compilation
	ViolatedInvariant string
	InvolvedClaimIDs []string
	FailClosed       bool
}

// AuthorityTypeOrder returns the precedence order for authority types.
// Lower values indicate higher precedence.
func AuthorityTypeOrder() map[AuthorityType]int {
	return map[AuthorityType]int{
		Sovereign:      0,
		Legal:          1,
		Regulatory:     2,
		Organizational: 3,
		Contractual:    4,
	}
}

// IsValidAuthorityType checks if an authority type is valid.
func IsValidAuthorityType(t AuthorityType) bool {
	switch t {
	case Sovereign, Legal, Regulatory, Organizational, Contractual:
		return true
	default:
		return false
	}
}

// IsValidClaimType checks if a claim type is valid.
func IsValidClaimType(t ClaimType) bool {
	switch t {
	case Permission, Prohibition, Obligation, Delegation:
		return true
	default:
		return false
	}
}

// IsValidEdgeType checks if an edge type is valid.
func IsValidEdgeType(t EdgeType) bool {
	switch t {
	case Delegates, Revokes, Supersedes:
		return true
	default:
		return false
	}
}