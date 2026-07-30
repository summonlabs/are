package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	if logger == nil {
		logger = &DefaultLogger{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = logger
}

func (c *AuthorityCompiler) getLogger() Logger {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logger
}

// Ingest ingests an authority source and normalizes it to AIR.
// Returns an error if the source is invalid.
func (c *AuthorityCompiler) Ingest(source AuthoritySource) (AuthorityArtifact, error) {
	if err := validateAuthoritySource(source); err != nil {
		return AuthorityArtifact{}, err
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
	if err := validateAuthoritySource(source); err != nil {
		return AuthorityArtifact{}, err
	}

	claims := []Claim{}
	var parseErrors []error

	if rawClaims, exists := source.Metadata["claims"]; exists {
		claimsData, ok := rawClaims.([]interface{})
		if !ok {
			return AuthorityArtifact{}, newValidationError("metadata.claims", "must be an array of claim objects", nil)
		}
		for _, claimData := range claimsData {
			claimDict, ok := claimData.(map[string]interface{})
			if !ok {
				parseErrors = append(parseErrors, newValidationError("metadata.claims", "each claim must be an object", nil))
				continue
			}
			claim, err := c.parseClaim(claimDict, source.ID)
			if err != nil {
				parseErrors = append(parseErrors, err)
				continue
			}
			claims = append(claims, claim)
		}
	}

	if len(parseErrors) > 0 {
		return AuthorityArtifact{}, &CompilationError{
			Stage:   "normalization",
			Message: fmt.Sprintf("failed to parse %d claims", len(parseErrors)),
			Err:     parseErrors[0],
		}
	}

	if err := validateRelationships(claims); err != nil {
		return AuthorityArtifact{}, &CompilationError{
			Stage:   "normalization",
			Message: "invalid claim relationship",
			Err:     err,
		}
	}

	sourceSnapshot, err := cloneAuthoritySource(source)
	if err != nil {
		return AuthorityArtifact{}, &CompilationError{
			Stage:   "normalization",
			Message: "source is not canonically serializable",
			Err:     err,
		}
	}
	if err := c.registerSource(sourceSnapshot); err != nil {
		return AuthorityArtifact{}, err
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

	var scopeData map[string]interface{}
	if rawScope, exists := claimDict["scope"]; exists {
		var ok bool
		scopeData, ok = rawScope.(map[string]interface{})
		if !ok {
			return Claim{}, newValidationError("scope", "claim scope must be an object", nil)
		}
	}
	scope, err := parseScope(scopeData)
	if err != nil {
		return Claim{}, err
	}

	var conditions map[string]interface{}
	if rawConditions, exists := claimDict["conditions"]; exists {
		conditionMap, ok := rawConditions.(map[string]interface{})
		if !ok {
			return Claim{}, newValidationError("conditions", "claim conditions must be an object", nil)
		}
		conditions, err = cloneConditions(conditionMap)
		if err != nil {
			return Claim{}, newValidationError("conditions", "claim conditions must be canonically serializable", err)
		}
		for _, relation := range []string{"delegates_to", "revokes", "supersedes"} {
			if value, exists := conditions[relation]; exists {
				target, ok := value.(string)
				if !ok || strings.TrimSpace(target) == "" {
					return Claim{}, newValidationError("conditions."+relation, "relationship target must be a non-empty claim ID", nil)
				}
			}
		}
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
		Conditions: conditions,
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
	var err error
	artifact, err = c.applyRevocations(artifact)
	if err != nil {
		return AuthorityArtifact{}, err
	}
	artifact, err = c.applySupersessions(artifact)
	if err != nil {
		return AuthorityArtifact{}, err
	}

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

	// Sort keys for deterministic iteration
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		group := grouped[key]
		used := make([]bool, len(group))
		for i := range group {
			if used[i] {
				continue
			}
			coextensive := []Claim{group[i]}
			used[i] = true
			for j := i + 1; j < len(group); j++ {
				if !used[j] && scopesEqual(group[i].Scope, group[j].Scope) && conditionsEqual(group[i].Conditions, group[j].Conditions) {
					coextensive = append(coextensive, group[j])
					used[j] = true
				}
			}

			hasPermission := false
			hasProhibition := false
			for _, claim := range coextensive {
				hasPermission = hasPermission || claim.Type == Permission
				hasProhibition = hasProhibition || claim.Type == Prohibition
			}
			if hasPermission && hasProhibition {
				conflicts = append(conflicts, coextensive)
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

	for _, claim := range claims {
		source, exists := sourcesCopy[claim.SourceID]
		if !exists {
			return nil, newValidationError("source_id", fmt.Sprintf("unknown source for claim %s: %s", claim.ID, claim.SourceID), nil)
		}
		if !IsValidAuthorityType(source.Type) {
			return nil, newValidationError("source.type", fmt.Sprintf("invalid authority type for source %s: %s", source.ID, source.Type), nil)
		}
	}

	sort.SliceStable(claims, func(i, j int) bool {
		claimA := claims[i]
		claimB := claims[j]

		sourceA := sourcesCopy[claimA.SourceID]
		sourceB := sourcesCopy[claimB.SourceID]

		keyA := precedenceKey(sourceA, claimA, authorityOrder, artifact.Graph)
		keyB := precedenceKey(sourceB, claimB, authorityOrder, artifact.Graph)

		if cmp := comparePrecedenceKeys(keyA, keyB); cmp != 0 {
			return cmp < 0
		}
		return claimA.ID < claimB.ID
	})

	topKey := precedenceKey(sourcesCopy[claims[0].SourceID], claims[0], authorityOrder, artifact.Graph)
	samePrecedence := []Claim{}
	for _, claim := range claims {
		key := precedenceKey(sourcesCopy[claim.SourceID], claim, authorityOrder, artifact.Graph)
		if comparePrecedenceKeys(topKey, key) != 0 {
			break
		}
		samePrecedence = append(samePrecedence, claim)
	}

	for _, claim := range samePrecedence {
		if claim.Type == Prohibition {
			winner := claim
			return &winner, nil
		}
	}

	return &claims[0], nil
}

func (c *AuthorityCompiler) applyRevocations(artifact AuthorityArtifact) (AuthorityArtifact, error) {
	return c.applyDestructiveRelationships(artifact, Revokes)
}

func (c *AuthorityCompiler) applySupersessions(artifact AuthorityArtifact) (AuthorityArtifact, error) {
	return c.applyDestructiveRelationships(artifact, Supersedes)
}

func (c *AuthorityCompiler) applyDestructiveRelationships(artifact AuthorityArtifact, edgeType EdgeType) (AuthorityArtifact, error) {
	removedIDs := make(map[string]bool)
	claimsByID := make(map[string]Claim, len(artifact.Claims))
	for _, claim := range artifact.Claims {
		claimsByID[claim.ID] = claim
	}

	for _, edge := range artifact.Graph.Edges {
		if edge.EdgeType != edgeType {
			continue
		}
		issuer, issuerExists := claimsByID[edge.FromID]
		target, targetExists := claimsByID[edge.ToID]
		if !issuerExists || !targetExists {
			return AuthorityArtifact{}, newValidationError("graph.edges", fmt.Sprintf("%s relationship references an inactive claim", edgeType), ErrInvalidEdgeReference)
		}
		if !scopesEqual(issuer.Scope, target.Scope) {
			return AuthorityArtifact{}, &ConflictError{
				ClaimIDs: []string{issuer.ID, target.ID},
				Message:  fmt.Sprintf("%s requires coextensive issuer and target scopes", edgeType),
			}
		}
		winner, err := c.applyPrecedence([]Claim{issuer, target}, artifact)
		if err != nil {
			return AuthorityArtifact{}, err
		}
		if winner == nil || winner.ID != issuer.ID {
			return AuthorityArtifact{}, &ConflictError{
				ClaimIDs: []string{issuer.ID, target.ID},
				Message:  fmt.Sprintf("%s issuer does not outrank target", edgeType),
			}
		}
		removedIDs[target.ID] = true
	}

	newClaims := make([]Claim, 0, len(artifact.Claims))
	for _, claim := range artifact.Claims {
		if !removedIDs[claim.ID] {
			newClaims = append(newClaims, claim)
		}
	}
	artifact.Claims = newClaims
	return artifact, nil
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
	proof, _ := c.emitProof(artifact)
	return proof
}

func (c *AuthorityCompiler) emitProof(artifact AuthorityArtifact) (string, error) {
	claimsList := make([]map[string]interface{}, 0, len(artifact.Claims))
	sortedClaims := make([]Claim, len(artifact.Claims))
	copy(sortedClaims, artifact.Claims)
	sort.Slice(sortedClaims, func(i, j int) bool {
		if sortedClaims[i].ID != sortedClaims[j].ID {
			return sortedClaims[i].ID < sortedClaims[j].ID
		}
		return sortedClaims[i].SourceID < sortedClaims[j].SourceID
	})

	for _, claim := range sortedClaims {
		claimsList = append(claimsList, canonicalClaimMap(claim))
	}

	nodeIDs := make([]string, 0, len(artifact.Graph.Nodes))
	for id := range artifact.Graph.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	nodes := make([]map[string]interface{}, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		nodes = append(nodes, map[string]interface{}{
			"key":   id,
			"claim": canonicalClaimMap(artifact.Graph.Nodes[id]),
		})
	}

	edges := append([]Edge(nil), artifact.Graph.Edges...)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromID != edges[j].FromID {
			return edges[i].FromID < edges[j].FromID
		}
		if edges[i].ToID != edges[j].ToID {
			return edges[i].ToID < edges[j].ToID
		}
		return edges[i].EdgeType < edges[j].EdgeType
	})
	edgeList := make([]map[string]interface{}, 0, len(edges))
	for _, edge := range edges {
		edgeList = append(edgeList, map[string]interface{}{
			"from_id": edge.FromID,
			"to_id":   edge.ToID,
			"type":    string(edge.EdgeType),
		})
	}

	sourceIDs := map[string]bool{artifact.SourceID: true}
	for _, claim := range artifact.Claims {
		sourceIDs[claim.SourceID] = true
	}
	for _, claim := range artifact.Graph.Nodes {
		sourceIDs[claim.SourceID] = true
	}
	delete(sourceIDs, "")
	sortedSourceIDs := make([]string, 0, len(sourceIDs))
	for id := range sourceIDs {
		sortedSourceIDs = append(sortedSourceIDs, id)
	}
	sort.Strings(sortedSourceIDs)

	c.mu.RLock()
	sources := make([]map[string]interface{}, 0, len(sortedSourceIDs))
	for _, id := range sortedSourceIDs {
		source, exists := c.sources[id]
		if !exists {
			c.mu.RUnlock()
			return "", newValidationError("source_id", fmt.Sprintf("unknown source in proof: %s", id), nil)
		}
		sources = append(sources, map[string]interface{}{
			"id":      source.ID,
			"type":    string(source.Type),
			"version": source.Version,
		})
	}
	c.mu.RUnlock()

	proofData := map[string]interface{}{
		"claims":       claimsList,
		"claims_count": len(artifact.Claims),
		"graph": map[string]interface{}{
			"edges": edgeList,
			"nodes": nodes,
		},
		"source_id": artifact.SourceID,
		"sources":   sources,
	}

	jsonBytes, err := json.MarshalIndent(proofData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("serialize authority proof: %w", err)
	}
	return string(jsonBytes), nil
}

// Process runs the full compilation pipeline.
// Thread-safe and supports context cancellation.
func (c *AuthorityCompiler) Process(source AuthoritySource) interface{} {
	return c.ProcessWithContext(context.Background(), source)
}

// ProcessWithContext runs the full compilation pipeline with context support.
func (c *AuthorityCompiler) ProcessWithContext(ctx context.Context, source AuthoritySource) interface{} {
	logger := c.getLogger()
	logger.Info("Starting compilation for source %s", source.ID)

	artifact, err := c.Normalize(ctx, source)
	if err != nil {
		logger.Error("Normalization failed: %v", err)
		return CompilationFailure{
			FailureStage:      "normalization",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  []string{},
			FailClosed:        true,
		}
	}
	logger.Info("Normalized %d claims", len(artifact.Claims))

	if err := c.Validate(artifact); err != nil {
		logger.Error("Validation failed: %v", err)
		return CompilationFailure{
			FailureStage:      "validation",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  getClaimIDs(artifact.Claims),
			FailClosed:        true,
		}
	}
	logger.Info("Validation passed")

	artifact, err = c.ResolveConflicts(ctx, artifact)
	if err != nil {
		logger.Error("Conflict resolution failed: %v", err)
		return CompilationFailure{
			FailureStage:      "resolution",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  getClaimIDs(artifact.Claims),
			FailClosed:        true,
		}
	}
	logger.Info("Conflict resolution complete, %d claims remaining", len(artifact.Claims))

	artifact = c.Compile(artifact)
	proof, err := c.emitProof(artifact)
	if err != nil {
		logger.Error("Proof serialization failed: %v", err)
		return CompilationFailure{
			FailureStage:      "compilation",
			ViolatedInvariant: err.Error(),
			InvolvedClaimIDs:  getClaimIDs(artifact.Claims),
			FailClosed:        true,
		}
	}
	c.Bind(artifact)

	logger.Info("Compilation successful for artifact %s", artifact.ID)
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

func validateAuthoritySource(source AuthoritySource) error {
	if source.ID == "" {
		return ErrEmptySourceID
	}
	if !IsValidAuthorityType(source.Type) {
		return newValidationError("type", fmt.Sprintf("invalid authority type: %s", source.Type), nil)
	}
	if source.Version != "" && semverRegex.FindStringSubmatch(source.Version) == nil {
		return newValidationError("version", fmt.Sprintf("invalid version: %s", source.Version), ErrInvalidVersion)
	}
	return nil
}

func parseScope(scopeData map[string]interface{}) (Scope, error) {
	jurisdictions, err := parseStringSlice(scopeData["jurisdictions"], "scope.jurisdictions")
	if err != nil {
		return Scope{}, err
	}
	operations, err := parseStringSlice(scopeData["operations"], "scope.operations")
	if err != nil {
		return Scope{}, err
	}
	timeStart, err := parseTimeField(scopeData["time_start"], "scope.time_start")
	if err != nil {
		return Scope{}, err
	}
	timeEnd, err := parseTimeField(scopeData["time_end"], "scope.time_end")
	if err != nil {
		return Scope{}, err
	}

	scope := Scope{
		Jurisdictions: jurisdictions,
		TimeStart:     timeStart,
		TimeEnd:       timeEnd,
		Operations:    operations,
	}
	if err := ValidateScopeWithErrors(scope); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

func parseStringSlice(value interface{}, field string) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	var raw []string
	switch values := value.(type) {
	case []string:
		raw = append(raw, values...)
	case []interface{}:
		raw = make([]string, 0, len(values))
		for _, item := range values {
			s, ok := item.(string)
			if !ok {
				return nil, newValidationError(field, "must contain only strings", nil)
			}
			raw = append(raw, s)
		}
	default:
		return nil, newValidationError(field, "must be a string slice", nil)
	}

	seen := make(map[string]bool, len(raw))
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		if strings.TrimSpace(value) == "" {
			return nil, newValidationError(field, "must not contain empty strings", nil)
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func parseTimeField(value interface{}, field string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	s, ok := value.(string)
	if !ok || s == "" {
		return nil, newValidationError(field, "must be an RFC3339 timestamp string", ErrInvalidScope)
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, newValidationError(field, "must be an RFC3339 timestamp string", err)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func cloneConditions(conditions map[string]interface{}) (map[string]interface{}, error) {
	cloned, ok := cloneRuntimeConditions(conditions)
	if !ok {
		return nil, fmt.Errorf("unsupported condition value")
	}
	if _, err := json.Marshal(cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}

func cloneAuthoritySource(source AuthoritySource) (AuthoritySource, error) {
	encoded, err := json.Marshal(source)
	if err != nil {
		return AuthoritySource{}, err
	}
	var cloned AuthoritySource
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return AuthoritySource{}, err
	}
	return cloned, nil
}

func (c *AuthorityCompiler) registerSource(source AuthoritySource) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, exists := c.sources[source.ID]; exists {
		existingBytes, err := json.Marshal(existing)
		if err != nil {
			return fmt.Errorf("serialize existing authority source: %w", err)
		}
		newBytes, err := json.Marshal(source)
		if err != nil {
			return fmt.Errorf("serialize authority source: %w", err)
		}
		if !bytes.Equal(existingBytes, newBytes) {
			return newValidationError("source.id", fmt.Sprintf("conflicting redefinition of authority source %s", source.ID), nil)
		}
		return nil
	}
	c.sources[source.ID] = source
	return nil
}

func validateRelationships(claims []Claim) error {
	claimsByID := make(map[string]Claim, len(claims))
	for _, claim := range claims {
		if _, exists := claimsByID[claim.ID]; exists {
			return newValidationError("claim.id", fmt.Sprintf("duplicate claim ID: %s", claim.ID), ErrInvalidClaim)
		}
		claimsByID[claim.ID] = claim
	}

	for _, issuer := range claims {
		for _, relationship := range []struct {
			key      string
			edgeType EdgeType
		}{
			{key: "delegates_to", edgeType: Delegates},
			{key: "revokes", edgeType: Revokes},
			{key: "supersedes", edgeType: Supersedes},
		} {
			rawTarget, exists := issuer.Conditions[relationship.key]
			if !exists {
				continue
			}
			targetID, ok := rawTarget.(string)
			if !ok || strings.TrimSpace(targetID) == "" {
				return newValidationError("conditions."+relationship.key, "relationship target must be a non-empty claim ID", nil)
			}
			target, exists := claimsByID[targetID]
			if !exists {
				return newValidationError("conditions."+relationship.key, fmt.Sprintf("relationship target does not exist: %s", targetID), ErrInvalidEdgeReference)
			}
			if relationship.edgeType == Delegates {
				if issuer.Action != "delegate" {
					return newValidationError("claim.action", fmt.Sprintf("delegation issuer %s must use action delegate", issuer.ID), ErrInvalidClaim)
				}
				if target.Type != Delegation {
					return newValidationError("conditions.delegates_to", fmt.Sprintf("delegation target %s must be a delegation claim", target.ID), ErrInvalidClaim)
				}
			}
		}
	}
	return nil
}

func scopesEqual(a, b Scope) bool {
	if !stringSetsEqual(a.Jurisdictions, b.Jurisdictions) || !stringSetsEqual(a.Operations, b.Operations) {
		return false
	}
	return timesEqual(a.TimeStart, b.TimeStart) && timesEqual(a.TimeEnd, b.TimeEnd)
}

func stringSetsEqual(a, b []string) bool {
	aSet := make(map[string]bool, len(a))
	bSet := make(map[string]bool, len(b))
	for _, value := range a {
		aSet[value] = true
	}
	for _, value := range b {
		bSet[value] = true
	}
	if len(aSet) != len(bSet) {
		return false
	}
	for value := range aSet {
		if !bSet[value] {
			return false
		}
	}
	return true
}

func timesEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func conditionsEqual(a, b map[string]interface{}) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	aBytes, aErr := json.Marshal(a)
	bBytes, bErr := json.Marshal(b)
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}

func canonicalClaimMap(claim Claim) map[string]interface{} {
	return map[string]interface{}{
		"action":     claim.Action,
		"conditions": claim.Conditions,
		"id":         claim.ID,
		"resource":   claim.Resource,
		"scope": map[string]interface{}{
			"jurisdictions": canonicalStringSet(claim.Scope.Jurisdictions),
			"operations":    canonicalStringSet(claim.Scope.Operations),
			"time_end":      canonicalProofTime(claim.Scope.TimeEnd),
			"time_start":    canonicalProofTime(claim.Scope.TimeStart),
		},
		"source_id": claim.SourceID,
		"subject":   claim.Subject,
		"type":      string(claim.Type),
	}
}

func canonicalStringSet(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func canonicalProofTime(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func generateUUID() string {
	return uuid.New().String()
}

func precedenceKey(source AuthoritySource, claim Claim, authorityOrder map[AuthorityType]int, graph AuthorityGraph) []interface{} {
	order := authorityOrder[source.Type]
	version := parseVersion(source.Version)
	versionKey := []int{-version[0], -version[1], -version[2]}
	depth := getDelegationDepth(claim, graph)

	return []interface{}{
		order,
		versionKey,
		depth,
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
		case []int:
			bv, ok := b[i].([]int)
			if !ok {
				return 1
			}
			for j := 0; j < len(av) && j < len(bv); j++ {
				if av[j] < bv[j] {
					return -1
				} else if av[j] > bv[j] {
					return 1
				}
			}
			if len(av) < len(bv) {
				return -1
			} else if len(av) > len(bv) {
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
