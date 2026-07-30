package core

import (
	"reflect"
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

// AuthorizationContext supplies the runtime facts required to evaluate scoped
// and conditional authority claims.
type AuthorizationContext struct {
	Jurisdiction string                 `json:"jurisdiction"`
	At           time.Time              `json:"at"`
	Attributes   map[string]interface{} `json:"attributes"`
}

// RuntimeInterface defines how runtime systems query ARE for authorization decisions.
// Thread-safe for concurrent authorization queries.
// Note: RuntimeInterface responses are advisory reflections of compiled authority.
// Runtime systems MUST enforce constraints independently.
type RuntimeInterface struct {
	artifact AuthorityArtifact
	valid    bool
	mu       sync.RWMutex
}

// NewRuntimeInterface creates a new thread-safe instance of RuntimeInterface.
// The artifact is defensively copied and validated. Invalid artifacts are retained
// only for inspection and always fail closed during runtime queries.
func NewRuntimeInterface(artifact AuthorityArtifact) *RuntimeInterface {
	cloned, cloneOK := cloneRuntimeArtifact(&artifact)
	valid := cloneOK && ValidateAirWithErrors(cloned) == nil

	return &RuntimeInterface{
		artifact: cloned,
		valid:    valid,
	}
}

// IsAuthorized checks if an action is authorized under the given authority.
// Legacy calls have no jurisdiction or condition attributes and therefore fail
// closed for claims that require either.
func (ri *RuntimeInterface) IsAuthorized(subject, action, resource string) map[string]interface{} {
	return ri.IsAuthorizedWithContext(subject, action, resource, AuthorizationContext{})
}

// IsAuthorizedWithContext checks if an action is authorized using explicit
// jurisdictional, temporal, and conditional runtime facts.
func (ri *RuntimeInterface) IsAuthorizedWithContext(subject, action, resource string, ctx AuthorizationContext) map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	if !ri.valid {
		return ri.deniedResult("Invalid authority artifact - failing closed")
	}
	if !validAuthorizationQuery(subject, action, resource) {
		return ri.deniedResult("Invalid authorization query - failing closed")
	}

	applicable := ri.applicableClaims(subject, action, resource, normalizeAuthorizationContext(ctx))

	// Check for prohibitions first (highest priority).
	for _, claim := range applicable {
		if claim.Type == Prohibition {
			return map[string]interface{}{
				"allowed":      false,
				"authority_id": claim.ID,
				"reason":       "Prohibited by authority",
				"scope":        ri.scopeToDict(claim.Scope),
			}
		}
	}

	// Check for permissions.
	for _, claim := range applicable {
		if claim.Type == Permission {
			return map[string]interface{}{
				"allowed":      true,
				"authority_id": claim.ID,
				"reason":       "Permitted by authority",
				"scope":        ri.scopeToDict(claim.Scope),
			}
		}
	}

	return ri.deniedResult("No applicable authority found - failing closed")
}

// GetObligations gets all obligations that apply to this context.
// Legacy calls omit contextual facts and fail closed for scoped or conditional
// obligations that cannot be evaluated safely.
func (ri *RuntimeInterface) GetObligations(subject, action, resource string) []map[string]interface{} {
	return ri.GetObligationsWithContext(subject, action, resource, AuthorizationContext{})
}

// GetObligationsWithContext gets all obligations that apply to the supplied
// jurisdictional, temporal, and conditional context.
func (ri *RuntimeInterface) GetObligationsWithContext(subject, action, resource string, ctx AuthorizationContext) []map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	obligations := []map[string]interface{}{}
	if !ri.valid || !validAuthorizationQuery(subject, action, resource) {
		return obligations
	}

	for _, claim := range ri.applicableClaims(subject, action, resource, normalizeAuthorizationContext(ctx)) {
		if claim.Type != Obligation {
			continue
		}
		obligations = append(obligations, map[string]interface{}{
			"claim_id":   claim.ID,
			"action":     claim.Action,
			"scope":      ri.scopeToDict(claim.Scope),
			"conditions": cloneRuntimeConditionsForResponse(claim.Conditions),
		})
	}
	return obligations
}

// GetAuthorityInfo returns detailed information about which authority applies.
// Legacy calls omit contextual facts and therefore exclude claims whose scope or
// conditions cannot be established.
func (ri *RuntimeInterface) GetAuthorityInfo(subject, action, resource string) map[string]interface{} {
	return ri.GetAuthorityInfoWithContext(subject, action, resource, AuthorizationContext{})
}

// GetAuthorityInfoWithContext returns detailed information about the authority
// applicable to the supplied runtime context.
func (ri *RuntimeInterface) GetAuthorityInfoWithContext(subject, action, resource string, ctx AuthorizationContext) map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	applicableClaims := []map[string]interface{}{}
	if ri.valid && validAuthorizationQuery(subject, action, resource) {
		for _, claim := range ri.applicableClaims(subject, action, resource, normalizeAuthorizationContext(ctx)) {
			applicableClaims = append(applicableClaims, map[string]interface{}{
				"id":         claim.ID,
				"type":       claim.Type,
				"scope":      ri.scopeToDict(claim.Scope),
				"conditions": cloneRuntimeConditionsForResponse(claim.Conditions),
			})
		}
	}

	return map[string]interface{}{
		"artifact_id":       ri.artifact.ID,
		"applicable_claims": applicableClaims,
		"total_claims":      len(ri.artifact.Claims),
	}
}

func (ri *RuntimeInterface) applicableClaims(subject, action, resource string, ctx AuthorizationContext) []Claim {
	applicable := make([]Claim, 0)
	for _, claim := range ri.artifact.Claims {
		if ri.claimApplies(claim, subject, action, resource, ctx) {
			applicable = append(applicable, claim)
		}
	}
	return applicable
}

func (ri *RuntimeInterface) claimApplies(claim Claim, subject, action, resource string, ctx AuthorizationContext) bool {
	if !ri.matches(claim.Subject, subject) ||
		!ri.matches(claim.Action, action) ||
		!ri.matches(claim.Resource, resource) {
		return false
	}

	if len(claim.Scope.Operations) > 0 && !containsRuntimeString(claim.Scope.Operations, action) {
		return false
	}
	if claim.Scope.TimeStart != nil && ctx.At.Before(*claim.Scope.TimeStart) {
		return false
	}
	if claim.Scope.TimeEnd != nil && ctx.At.After(*claim.Scope.TimeEnd) {
		return false
	}
	if len(claim.Scope.Jurisdictions) > 0 {
		if ctx.Jurisdiction == "" || !containsRuntimeString(claim.Scope.Jurisdictions, ctx.Jurisdiction) {
			return false
		}
	}

	for key, expected := range claim.Conditions {
		if isRelationshipCondition(key) {
			continue
		}
		actual, exists := ctx.Attributes[key]
		if !exists || !reflect.DeepEqual(expected, actual) {
			return false
		}
	}

	return true
}

func (ri *RuntimeInterface) matches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == value {
		return true
	}

	// Handle wildcard patterns like "/code/*".
	if strings.Contains(pattern, "*") {
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
		"jurisdictions": append([]string(nil), scope.Jurisdictions...),
		"time_start":    timeStart,
		"time_end":      timeEnd,
		"operations":    append([]string(nil), scope.Operations...),
	}
}

func (ri *RuntimeInterface) deniedResult(reason string) map[string]interface{} {
	return map[string]interface{}{
		"allowed":      false,
		"authority_id": ri.artifact.ID,
		"reason":       reason,
		"scope":        map[string]interface{}{},
	}
}

// GetArtifact returns a deep copy of the underlying artifact (thread-safe).
func (ri *RuntimeInterface) GetArtifact() AuthorityArtifact {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	artifact, ok := cloneRuntimeArtifact(&ri.artifact)
	if !ok {
		return AuthorityArtifact{}
	}
	return artifact
}

func validAuthorizationQuery(subject, action, resource string) bool {
	return strings.TrimSpace(subject) != "" &&
		strings.TrimSpace(action) != "" &&
		strings.TrimSpace(resource) != ""
}

func normalizeAuthorizationContext(ctx AuthorizationContext) AuthorizationContext {
	if ctx.At.IsZero() {
		ctx.At = time.Now().UTC()
	} else {
		ctx.At = ctx.At.UTC()
	}
	return ctx
}

func containsRuntimeString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func isRelationshipCondition(key string) bool {
	switch key {
	case "delegates_to", "revokes", "supersedes":
		return true
	default:
		return false
	}
}

func cloneRuntimeArtifact(artifact *AuthorityArtifact) (AuthorityArtifact, bool) {
	cloned := AuthorityArtifact{
		ID:          artifact.ID,
		SourceID:    artifact.SourceID,
		GeneratedAt: artifact.GeneratedAt,
	}

	if artifact.Claims != nil {
		cloned.Claims = make([]Claim, len(artifact.Claims))
		for i, claim := range artifact.Claims {
			var ok bool
			cloned.Claims[i], ok = cloneRuntimeClaim(claim)
			if !ok {
				return AuthorityArtifact{}, false
			}
		}
	}

	if artifact.Graph.Nodes != nil {
		cloned.Graph.Nodes = make(map[string]Claim, len(artifact.Graph.Nodes))
		for id, claim := range artifact.Graph.Nodes {
			clonedClaim, ok := cloneRuntimeClaim(claim)
			if !ok {
				return AuthorityArtifact{}, false
			}
			cloned.Graph.Nodes[id] = clonedClaim
		}
	}
	if artifact.Graph.Edges != nil {
		cloned.Graph.Edges = append([]Edge(nil), artifact.Graph.Edges...)
	}

	return cloned, true
}

func cloneRuntimeClaim(claim Claim) (Claim, bool) {
	conditions, ok := cloneRuntimeConditions(claim.Conditions)
	if !ok {
		return Claim{}, false
	}

	return Claim{
		ID:       claim.ID,
		Type:     claim.Type,
		Subject:  claim.Subject,
		Action:   claim.Action,
		Resource: claim.Resource,
		Scope: Scope{
			Jurisdictions: append([]string(nil), claim.Scope.Jurisdictions...),
			TimeStart:     cloneRuntimeTime(claim.Scope.TimeStart),
			TimeEnd:       cloneRuntimeTime(claim.Scope.TimeEnd),
			Operations:    append([]string(nil), claim.Scope.Operations...),
		},
		Conditions: conditions,
		SourceID:   claim.SourceID,
	}, true
}

func cloneRuntimeTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneRuntimeConditions(conditions map[string]interface{}) (map[string]interface{}, bool) {
	if conditions == nil {
		return nil, true
	}
	cloned := make(map[string]interface{}, len(conditions))
	for key, value := range conditions {
		clonedValue, ok := cloneRuntimeValue(reflect.ValueOf(value), 0)
		if !ok {
			return nil, false
		}
		if clonedValue.IsValid() {
			cloned[key] = clonedValue.Interface()
		} else {
			cloned[key] = nil
		}
	}
	return cloned, true
}

func cloneRuntimeConditionsForResponse(conditions map[string]interface{}) map[string]interface{} {
	cloned, ok := cloneRuntimeConditions(conditions)
	if !ok {
		return nil
	}
	return cloned
}

func cloneRuntimeValue(value reflect.Value, depth int) (reflect.Value, bool) {
	if depth > 64 {
		return reflect.Value{}, false
	}
	if !value.IsValid() {
		return reflect.Value{}, true
	}

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type()), true
		}
		cloned, ok := cloneRuntimeValue(value.Elem(), depth+1)
		if !ok {
			return reflect.Value{}, false
		}
		result := reflect.New(value.Type()).Elem()
		result.Set(cloned)
		return result, true

	case reflect.Ptr:
		if value.IsNil() {
			return reflect.Zero(value.Type()), true
		}
		cloned, ok := cloneRuntimeValue(value.Elem(), depth+1)
		if !ok {
			return reflect.Value{}, false
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(cloned)
		return result, true

	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type()), true
		}
		if value.Type().Key().Kind() != reflect.String {
			return reflect.Value{}, false
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			clonedValue, ok := cloneRuntimeValue(iterator.Value(), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			result.SetMapIndex(iterator.Key(), clonedValue)
		}
		return result, true

	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type()), true
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := 0; i < value.Len(); i++ {
			cloned, ok := cloneRuntimeValue(value.Index(i), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			result.Index(i).Set(cloned)
		}
		return result, true

	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			cloned, ok := cloneRuntimeValue(value.Index(i), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			result.Index(i).Set(cloned)
		}
		return result, true

	case reflect.Struct:
		if value.Type() == reflect.TypeOf(time.Time{}) {
			return value, true
		}
		return reflect.Value{}, false

	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128,
		reflect.String:
		return value, true

	default:
		return reflect.Value{}, false
	}
}
