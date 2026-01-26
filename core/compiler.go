package core

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// semverRegex matches semantic version strings (e.g., "1.2.3", "v2.0.0-beta").
var semverRegex = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// Logger interface for dependency injection of logging.
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// DefaultLogger provides a no-op logger implementation.
type DefaultLogger struct{}

func (l *DefaultLogger) Debug(msg string, args ...interface{}) {}
func (l *DefaultLogger) Info(msg string, args ...interface{})  {}
func (l *DefaultLogger) Warn(msg string, args ...interface{})  {}
func (l *DefaultLogger) Error(msg string, args ...interface{}) {}

// AuthorityCompiler transforms authority sources into executable artifacts.
// Thread-safe for concurrent use across multiple goroutines.
type AuthorityCompiler struct {
	sources map[string]AuthoritySource
	mu      sync.RWMutex
	logger  Logger
}

// NewAuthorityCompiler creates a new thread-safe AuthorityCompiler instance.
func NewAuthorityCompiler() *AuthorityCompiler {
	return &AuthorityCompiler{
		sources: make(map[string]AuthoritySource),
		logger:  &DefaultLogger{},
	}
}

// SetLogger sets the logger for the compiler.
func (c *AuthorityCompiler) SetLogger(logger Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = logger
}

// Ingest ingests an authority source and normalizes it to AIR.
// Returns an error if the source is invalid.
func (c *AuthorityCompiler) Ingest(source AuthoritySource) (AuthorityArtifact, error) {
	if source.ID == "" {
		return AuthorityArtifact{}, ErrEmptySourceID
	}

	artifact := AuthorityArtifact{
		ID:          generateUUID(),
		SourceID:    source.ID,
		Claims:      []Claim{},
		Graph:       AuthorityGraph{Nodes: make(map[string]Claim), Edges: []Edge{}},
		GeneratedAt: time.Now().UTC(),
	}
	return artifact, nil
}

// Normalize converts authority input into canonical AIR.
// Thread-safe: acquires write lock to store source.
func (c *AuthorityCompiler) Normalize(ctx context.Context, source AuthoritySource) (AuthorityArtifact, error) {
	if err := ctx.Err(); err != nil {
		return AuthorityArtifact{}, err
	}

	if source.ID == "" {
		return AuthorityArtifact{}, ErrEmptySourceID
	}

	// Store source for later precedence resolution (thread-safe)
	c.mu.Lock()
	c.sources[source.ID] = source
	c.mu.Unlock()

	claims := []Claim{}
	var parseErrors []error

	if claimsData, ok := source.Metadata["claims"].([]interface{}); ok {
		for _, claimData := range claimsData {
			if claimDict, ok := claimData.(map[string]interface{}); ok {
				claim, err := c.parseClaim(claimDict, source.ID)
				if err != nil {
					parseErrors = append(parseErrors, err)
					continue
				}
				claims = append(claims, claim)
			}
		}
	}

	if len(parseErrors) > 0 {
		return AuthorityArtifact{}, &CompilationError{
			Stage:   "normalization",
			Message: fmt.Sprintf("failed to parse %d claims", len(parseErrors)),
			Err:     parseErrors[0],
		}
	}

	graph := c.buildGraph(claims)

	return AuthorityArtifact{
		ID:          generateUUID(),
		SourceID:    source.ID,
		Claims:      claims,
		Graph:       graph,
		GeneratedAt: time.Now().UTC(),
	}, nil
}

func (c *AuthorityCompiler) parseClaim(claimDict map[string]interface{}, sourceID string) (Claim, error) {
	id, ok := claimDict["id"].(string)
	if !ok || id == "" {
		return Claim{}, newValidationError("id", "claim ID is required", nil)
	}
	claimType, ok := claimDict["type"].(string)
	if !ok || claimType == "" {
		return Claim{}, newValidationError("type", "claim type is required", nil)
	}
	if !IsValidClaimType(ClaimType(claimType)) {
		return Claim{}, newValidationError("type", fmt.Sprintf("invalid claim type: %s", claimType), nil)
	}

	scopeData, _ := claimDict["scope"].(map[string]interface{})
	jurisdictions := []string{}
	if j, ok := scopeData["jurisdictions"].([]interface{}); ok {
		for _, v := range j {
			if s, ok := v.(string); ok {
				jurisdictions = append(jurisdictions, s)
			}
		}
	}

	timeStart := parseTime(scopeData["time_start"])
	timeEnd := parseTime(scopeData["time_end"])

	operations := []string{}
	if o, ok := scopeData["operations"].([]interface{}); ok {
		for _, v := range o {
			if s, ok := v.(string); ok {
				operations = append(operations, s)
			}
		}
	}

	scope := Scope{
		Jurisdictions: jurisdictions,
		TimeStart:     timeStart,
		TimeEnd:       timeEnd,
		Operations:    operations,
	}

	subject, _ := claimDict["subject"].(string)
	if subject == "" {
		return Claim{}, newValidationError("subject", "claim subject is required", nil)
	}
	action, _ := claimDict["action"].(string)
	if action == "" {
		return Claim{}, newValidationError("action", "claim action is required", nil)
	}
	resource, _ := claimDict["resource"].(string)
	if resource == "" {
		return Claim{}, newValidationError("resource", "claim resource is required", nil)
	}

	return Claim{
		ID:         id,
		Type:       ClaimType(claimType),
		Subject:    subject,
		Action:     action,
		Resource:   resource,
		Scope:      scope,
		Conditions: convertMapInterface(claimDict["conditions"]),
		SourceID:   sourceID,
	}, nil
}

func (c *AuthorityCompiler) buildGraph(claims []Claim) AuthorityGraph {
	nodes := make(map[string]Claim)
	edges := []Edge{}

	// First pass: add all nodes
	for _, claim := range claims {
		nodes[claim.ID] = claim
	}

	// Second pass: add edges (now all nodes exist)
	for _, claim := range claims {
		if claim.Conditions != nil {
			if delegatesTo, ok := claim.Conditions["delegates_to"].(string); ok {
				if _, exists := nodes[delegatesTo]; exists {
					edges = append(edges, Edge{
						FromID:   claim.ID,
						ToID:     delegatesTo,
						EdgeType: Delegates,
					})
				}
			}

			if revokes, ok := claim.Conditions["revokes"].(string); ok {
				if _, exists := nodes[revokes]; exists {
					edges = append(edges, Edge{
						FromID:   claim.ID,
						ToID:     revokes,
						EdgeType: Revokes,
					})
				}
			}

			if supersedes, ok := claim.Conditions["supersedes"].(string); ok {
				if _, exists := nodes[supersedes]; exists {
					edges = append(edges, Edge{
						FromID:   claim.ID,
						ToID:     supersedes,
						EdgeType: Supersedes,
					})
				}
			}
		}
	}

	// Sort edges for deterministic output
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromID != edges[j].FromID {
			return edges[i].FromID < edges[j].FromID
		}
		if edges[i].ToID != edges[j].ToID {
			return edges[i].ToID < edges[j].ToID
		}
		return edges[i].EdgeType < edges[j].EdgeType
	})

	return AuthorityGraph{Nodes: nodes, Edges: edges}
}

// Validate validates the AIR for structural correctness and scope consistency.
// Returns nil if valid, error describing the validation failure otherwise.
func (c *AuthorityCompiler) Validate(artifact AuthorityArtifact) error {
	return ValidateAirWithErrors(artifact)
}

// ResolveConflicts resolves conflicts in authority claims (fail-closed by default).
// Returns the resolved artifact or an error if conflicts cannot be resolved.
func (c *AuthorityCompiler) ResolveConflicts(ctx context.Context, artifact AuthorityArtifact) (AuthorityArtifact, error) {
	if err := ctx.Err(); err != nil {
		return AuthorityArtifact{}, err
	}

	// First, handle revocations and supersessions
	artifact = c.applyRevocations(artifact)
	artifact = c.applySupersessions(artifact)

	// Then handle remaining conflicts via precedence
	conflicts := c.findConflicts(artifact.Claims)

	for _, conflictGroup := range conflicts {
		winner, err := c.applyPrecedence(conflictGroup, artifact)
		if err != nil {
			return AuthorityArtifact{}, err
		}
		if winner == nil {
			claimIDs := make([]string, len(conflictGroup))
			for i, claim := range conflictGroup {
				claimIDs[i] = claim.ID
			}
			return AuthorityArtifact{}, &ConflictError{
				ClaimIDs: claimIDs,
				Message:  "unresolvable conflict - failing closed",
			}
		}

		losingClaimIDs := make(map[string]bool)
		for _, claim := range conflictGroup {
			if claim.ID != winner.ID {
				losingClaimIDs[claim.ID] = true
			}
		}

		newClaims := []Claim{}
		for _, claim := range artifact.Claims {
			if !losingClaimIDs[claim.ID] {
				newClaims = append(newClaims, claim)
			}
		}
		artifact.Claims = newClaims
	}

	artifact.Graph = c.buildGraph(artifact.Claims)
	return artifact, nil
}

func (c *AuthorityCompiler) findConflicts(claims []Claim) [][]Claim {
	conflicts := [][]Claim{}
	grouped := make(map[string][]Claim)

	for _, claim := range claims {
		// Skip delegation and obligation - they don't conflict with permissions/prohibitions
		if claim.Type == Delegation || claim.Type == Obligation {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", claim.Subject, claim.Action, claim.Resource)
		grouped[key] = append(grouped[key], claim)
	}

	// Only conflicting if there are DIFFERENT claim types (permission vs prohibition)
	// or multiple claims of the same type (which one wins?)
	// Sort keys for deterministic iteration
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		group := grouped[key]
		if len(group) > 1 {
			types := make(map[ClaimType]bool)
			for _, c := range group {
				types[c.Type] = true
			}
			if len(types) > 1 || len(group) > 1 {
				conflicts = append(conflicts, group)
			}
		}
	}

	return conflicts
}

func (c *AuthorityCompiler) applyPrecedence(claims []Claim, artifact AuthorityArtifact) (*Claim, error) {
	if len(claims) == 0 {
		return nil, nil
	}

	authorityOrder := AuthorityTypeOrder()

	// Thread-safe read of sources
	c.mu.RLock()
	sourcesCopy := make(map[string]AuthoritySource, len(c.sources))
	for k, v := range c.sources {
		sourcesCopy[k] = v
	}
	c.mu.RUnlock()

	sort.Slice(claims, func(i, j int) bool {
		claimA := claims[i]
		claimB := claims[j]

		sourceA := sourcesCopy[claimA.SourceID]
		sourceB := sourcesCopy[claimB.SourceID]

		keyA := precedenceKey(sourceA, claimA, authorityOrder, artifact.Graph)
		keyB := precedenceKey(sourceB, claimB, authorityOrder, artifact.Graph)

		return comparePrecedenceKeys(keyA, keyB) < 0
	})

	return &claims[0], nil
}

func (c *AuthorityCompiler) applyRevocations(artifact AuthorityArtifact) AuthorityArtifact {
	revokedIDs := make(map[string]bool)
	for _, edge := range artifact.Graph.Edges {
		if edge.EdgeType == Revokes {
			revokedIDs[edge.ToID] = true
		}
	}

	newClaims := []Claim{}
	for _, claim := range artifact.Claims {
		if !revokedIDs[claim.ID] {
			newClaims = append(newClaims, claim)
		}
	}
	artifact.Claims = newClaims

	return artifact
}

func (c *AuthorityCompiler) applySupersessions(artifact AuthorityArtifact) AuthorityArtifact {
	supersededIDs := make(map[string]bool)
	for _, edge := range artifact.Graph.Edges {
		if edge.EdgeType == Supersedes {
			supersededIDs[edge.ToID] = true
		}
	}

	newClaims := []Claim{}
	for _, claim := range artifact.Claims {
		if !supersededIDs[claim.ID] {
			newClaims = append(newClaims, claim)
		}
	}
	artifact.Claims = newClaims

	return artifact
}

// Compile generates executable enforcement artifacts.
func (c *AuthorityCompiler) Compile(artifact AuthorityArtifact) AuthorityArtifact {
	// Placeholder for compilation logic
	return artifact
}

// Bind attaches compiled artifacts to downstream systems.
func (c *AuthorityCompiler) Bind(artifact AuthorityArtifact) {
	// Placeholder for binding logic
}

// Returns deterministic JSON output sorted by keys.
func (c *AuthorityCompiler) EmitProof(artifact AuthorityArtifact) string {
	// Build claims list deterministically (sorted by ID)
	claimsList := make([]map[string]interface{}, 0, len(artifact.Claims))
	sortedClaims := make([]Claim, len(artifact.Claims))
	copy(sortedClaims, artifact.Claims)
	sort.Slice(sortedClaims, func(i, j int) bool {
		return sortedClaims[i].ID < sortedClaims[j].ID
	})

	for _, claim := range sortedClaims {
		claimsList = append(claimsList, map[string]interface{}{
			"action":    claim.Action,
			"id":        claim.ID,
			"resource":  claim.Resource,
			"source_id": claim.SourceID,
			"subject":   claim.Subject,
			"type":      string(claim.Type),
		})
	}

	proofData := map[string]interface{}{
		"artifact_id":  artifact.ID,
		"claims":       claimsList,
		"claims_count": len(artifact.Claims),
		"generated_at": artifact.GeneratedAt.Format(time.RFC3339),
		"graph": map[string]interface{}{
			"edges": len(artifact.Graph.Edges),
			"nodes": len(artifact.Graph.Nodes),
		},
		"source_id": artifact.SourceID,
	}

	jsonBytes, _ := json.MarshalIndent(proofData, "", "  ")
	return string(jsonBytes)
}

// Process runs the full compilation pipeline.
// Thread-safe and supports context cancellation.
func (c *AuthorityCompiler) Process(source AuthoritySource) interface{} {
	return c.ProcessWithContext(context.Background(), source)
}

// ProcessWithContext runs the full compilation pipeline with context support.
func (c *AuthorityCompiler) ProcessWithContext(ctx context.Context, source AuthoritySource) interface{} {
	c.logger.Info("Starting compilation for source %s", source.ID)

	artifact, err := c.Normalize(ctx, source)
	if err != nil {
		c.logger.Error("Normalization failed: %v", err)
		return CompilationFailure{
			FailureStage:      "normalization",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  []string{},
			FailClosed:        true,
		}
	}
	c.logger.Info("Normalized %d claims", len(artifact.Claims))

	if err := c.Validate(artifact); err != nil {
		c.logger.Error("Validation failed: %v", err)
		return CompilationFailure{
			FailureStage:     "validation",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  getClaimIDs(artifact.Claims),
			FailClosed:       true,
		}
	}
	c.logger.Info("Validation passed")

	artifact, err = c.ResolveConflicts(ctx, artifact)
	if err != nil {
		c.logger.Error("Conflict resolution failed: %v", err)
		return CompilationFailure{
			FailureStage:      "resolution",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  getClaimIDs(artifact.Claims),
			FailClosed:        true,
		}
	}
	c.logger.Info("Conflict resolution complete, %d claims remaining", len(artifact.Claims))

	artifact = c.Compile(artifact)
	c.Bind(artifact)
	proof := c.EmitProof(artifact)

	c.logger.Info("Compilation successful for artifact %s", artifact.ID)
	return CompilationSuccess{
		Artifact: artifact,
		Proof:    proof,
	}
}

func getClaimIDs(claims []Claim) []string {
	ids := make([]string, len(claims))
	for i, claim := range claims {
		ids[i] = claim.ID
	}
	sort.Strings(ids) // Deterministic output
	return ids
}

func parseTime(t interface{}) *time.Time {
	if t == nil {
		return nil
	}
	if s, ok := t.(string); ok {
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil
		}
		return &parsed
	}
	return nil
}

func convertMapInterface(m interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	if mm, ok := m.(map[string]interface{}); ok {
		return mm
	}
	return nil
}

func generateUUID() string {
	return uuid.New().String()
}

func precedenceKey(source AuthoritySource, claim Claim, authorityOrder map[AuthorityType]int, graph AuthorityGraph) []interface{} {
	order := authorityOrder[source.Type]
	version := parseVersion(source.Version)
	depth := getDelegationDepth(claim, graph)
	specificity := getScopeSpecificity(claim.Scope)

	return []interface{}{
		order,
		version,
		depth,
		-specificity,
	}
}

func comparePrecedenceKeys(a, b []interface{}) int {
	for i := range a {
		if i >= len(b) {
			return 1
		}
		switch av := a[i].(type) {
		case int:
			bv, ok := b[i].(int)
			if !ok {
				return -1
			}
			if av < bv {
				return -1
			} else if av > bv {
				return 1
			}
		case string:
			bv, ok := b[i].(string)
			if !ok {
				return 1
			}
			if av < bv {
				return -1
			} else if av > bv {
				return 1
			}
		}
	}
	if len(a) < len(b) {
		return -1
	}
	return 0
}

func parseVersion(versionStr string) []int {
	if versionStr == "" {
		return []int{0, 0, 0}
	}

	matches := semverRegex.FindStringSubmatch(versionStr)
	if matches == nil {
		return []int{0, 0, 0}
	}

	major, _ := strconv.Atoi(matches[1])
	minor := 0
	patch := 0
	if len(matches) > 2 && matches[2] != "" {
		minor, _ = strconv.Atoi(matches[2])
	}
	if len(matches) > 3 && matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
	}

	return []int{major, minor, patch}
}

func getDelegationDepth(claim Claim, graph AuthorityGraph) int {
	depth := 0
	currentID := claim.ID
	visited := make(map[string]bool)

	for currentID != "" {
		if visited[currentID] {
			return 999 // Cycle detected (shouldn't happen if validation passed)
		}
		visited[currentID] = true

		// Find parent delegation
		parent := ""
		for _, edge := range graph.Edges {
			if edge.ToID == currentID && edge.EdgeType == Delegates {
				parent = edge.FromID
				depth++
				break
			}
		}

		if parent == "" {
			break
		}
		currentID = parent
	}

	return depth
}

func getScopeSpecificity(scope Scope) int {
	specificity := 0
	specificity += len(scope.Jurisdictions)
	specificity += len(scope.Operations)
	// Time bounds make it more specific
	if scope.TimeStart != nil {
		specificity -= 10
	}
	if scope.TimeEnd != nil {
		specificity -= 10
	}
	return specificity
}