package license

import (
	"path"
	"strings"
	"time"
)

// Customer represents the licensed customer organization, tenant, and primary contact.
type Customer struct {
	// Name is the legal organization or display name of the customer (required).
	Name string `json:"name"`

	// Email is the administrator or billing contact email (optional).
	Email string `json:"email,omitempty"`

	// OrgID is the immutable tenant identifier, UUID, or CRM account ID (optional).
	OrgID string `json:"org_id,omitempty"`
}

// Scope defines operational boundaries restricting where and on what infrastructure the license is authorized.
// Any dimension left nil or empty is unrestricted (open to all targets).
type Scope struct {
	// Environments: authorized deployment environments (e.g., ["production"], ["staging", "dev"], ["*"]).
	Environments []string `json:"environments,omitempty"`

	// Accounts: authorized cloud tenant or account IDs (e.g., AWS Account IDs ["123456789012"]).
	Accounts []string `json:"accounts,omitempty"`

	// Regions: authorized geographic or cloud regions (e.g., ["us-east-1", "eu-west-*"]).
	Regions []string `json:"regions,omitempty"`

	// Clusters: authorized cluster IDs or ARNs (e.g., Kubernetes cluster UIDs, ECS clusters).
	Clusters []string `json:"clusters,omitempty"`

	// Namespaces: authorized project hierarchies, organizations, or groups (e.g., ["gitlab.com/acme-corp/*"]).
	Namespaces []string `json:"namespaces,omitempty"`

	// Hosts: authorized hostnames, FQDNs, or domain patterns (e.g., ["*.acme.corp", "runner-*.internal"]).
	Hosts []string `json:"hosts,omitempty"`

	// Custom: arbitrary product-specific scoping dimensions.
	Custom map[string][]string `json:"custom,omitempty"`
}

// Claims represents the license payload containing identity, validity periods,
// plan tiers, entitlements, and resource limits.
type Claims struct {
	// ID is the unique identifier for this license (e.g. UUIDv4).
	ID string `json:"id"`

	// KeyID optionally identifies the signing key used to issue this token (e.g., "divmora-2026-root" or key fingerprint).
	KeyID string `json:"kid,omitempty"`

	// Customer contains the customer organization identity and tenant details.
	Customer Customer `json:"customer"`

	// Product is the name of the software product (e.g., "gitlab-fleet-governor", "otel-aws-log-processor").
	Product string `json:"product"`

	// Plan designates the subscription or license tier (e.g., "community", "starter", "pro", "enterprise", "trial").
	Plan string `json:"plan"`

	// IssuedAt is the timestamp when the license was created.
	IssuedAt time.Time `json:"issued_at"`

	// NotBefore is the earliest timestamp when the license becomes valid.
	// If zero, the license is valid immediately upon issuance.
	NotBefore time.Time `json:"not_before,omitempty"`

	// ExpiresAt is the timestamp when the license expires.
	// Zero time indicates a perpetual license.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// GracePeriodDays specifies the allowed post-expiration grace period in days.
	// When ExpiresAt has passed, the license remains active in grace period for this duration.
	GracePeriodDays int `json:"grace_period_days,omitempty"`

	// Features is the list of enabled feature flags/entitlements.
	Features []string `json:"features,omitempty"`

	// Limits is a map of quota thresholds (e.g., {"max_nodes": 50, "max_runners": 100, "max_log_mb_per_day": 50000}).
	// A value of -1 denotes unlimited.
	Limits map[string]int64 `json:"limits,omitempty"`

	// Scope defines operational infrastructure, environment, account, region, namespace, and host boundaries.
	Scope *Scope `json:"scope,omitempty"`

	// Environment restricts usage to a designated environment (e.g., "production", "staging", "dev").
	Environment string `json:"environment,omitempty"`

	// Fingerprint binds the license to a specific cluster ID, hardware signature, or machine hash.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Metadata contains arbitrary key-value custom properties.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsPerpetual reports whether the license has no expiration date.
func (c *Claims) IsPerpetual() bool {
	return c.ExpiresAt.IsZero()
}

// EffectiveExpiration returns the absolute cutoff timestamp after which the license
// is completely expired and terminated (accounting for ExpiresAt + GracePeriodDays).
// If the license is perpetual, it returns zero time.
func (c *Claims) EffectiveExpiration() time.Time {
	if c.IsPerpetual() {
		return time.Time{}
	}
	if c.GracePeriodDays > 0 {
		return c.ExpiresAt.Add(time.Duration(c.GracePeriodDays) * 24 * time.Hour)
	}
	return c.ExpiresAt
}

// IsInGracePeriod reports whether the license has passed ExpiresAt but remains
// within its designated GracePeriodDays at the current time.
func (c *Claims) IsInGracePeriod() bool {
	return c.IsInGracePeriodAt(time.Now())
}

// IsInGracePeriodAt reports whether the license is in grace period at reference time t.
func (c *Claims) IsInGracePeriodAt(t time.Time) bool {
	if c.IsPerpetual() || c.GracePeriodDays <= 0 {
		return false
	}
	cutoff := c.EffectiveExpiration()
	return t.After(c.ExpiresAt) && (t.Before(cutoff) || t.Equal(cutoff))
}

// GraceDaysRemaining returns the number of full grace period days remaining if the license
// is currently operating in its grace period. If not in grace period, it returns 0.
func (c *Claims) GraceDaysRemaining() int {
	return c.GraceDaysRemainingAt(time.Now())
}

// GraceDaysRemainingAt returns the number of full grace period days remaining at reference time t.
func (c *Claims) GraceDaysRemainingAt(t time.Time) int {
	if !c.IsInGracePeriodAt(t) {
		return 0
	}
	diff := c.EffectiveExpiration().Sub(t)
	if diff <= 0 {
		return 0
	}
	return int(diff.Hours() / 24)
}

// IsExpired reports whether the license has passed its initial expiration date.
// Note: An expired license may still be active if it is currently in its grace period.
func (c *Claims) IsExpired() bool {
	return c.IsExpiredAt(time.Now())
}

// IsExpiredAt reports whether the license has passed its initial expiration date at time t.
func (c *Claims) IsExpiredAt(t time.Time) bool {
	if c.IsPerpetual() {
		return false
	}
	return t.After(c.ExpiresAt)
}

// IsActive reports whether the license is currently operational (valid NotBefore and before EffectiveExpiration).
func (c *Claims) IsActive() bool {
	return c.IsActiveAt(time.Now())
}

// IsActiveAt reports whether the license is operational at time t.
func (c *Claims) IsActiveAt(t time.Time) bool {
	if !c.NotBefore.IsZero() && t.Before(c.NotBefore) {
		return false
	}
	if c.IsPerpetual() {
		return true
	}
	return !c.IsExpiredAt(t) || c.IsInGracePeriodAt(t)
}

// Status represents the operational lifecycle state of a license.
type Status string

const (
	// StatusActive indicates the license is within its primary validity window before expiration.
	StatusActive Status = "ACTIVE"
	// StatusGracePeriod indicates the license has passed ExpiresAt but is actively permitted during its grace period.
	StatusGracePeriod Status = "GRACE_PERIOD"
	// StatusExpired indicates the license has exceeded both its expiration date and grace period cutoff.
	StatusExpired Status = "EXPIRED"
	// StatusNotYetValid indicates the license NotBefore timestamp is in the future.
	StatusNotYetValid Status = "NOT_YET_VALID"
)

// Status returns the operational lifecycle Status of the license at the current time.
func (c *Claims) Status() Status {
	return c.StatusAt(time.Now())
}

// StatusAt returns the operational lifecycle Status of the license at reference time t.
func (c *Claims) StatusAt(t time.Time) Status {
	if !c.NotBefore.IsZero() && t.Before(c.NotBefore) {
		return StatusNotYetValid
	}
	if c.IsPerpetual() {
		return StatusActive
	}
	if c.IsInGracePeriodAt(t) {
		return StatusGracePeriod
	}
	if t.After(c.EffectiveExpiration()) {
		return StatusExpired
	}
	return StatusActive
}

// DaysRemaining returns the number of full days remaining before expiration.
// If the license is perpetual, it returns -1.
// If the license is already expired, it returns 0.
func (c *Claims) DaysRemaining() int {
	if c.IsPerpetual() {
		return -1
	}
	diff := time.Until(c.ExpiresAt)
	if diff <= 0 {
		return 0
	}
	return int(diff.Hours() / 24)
}

// IsValidForProduct checks whether the license is valid for the given product name.
// It supports:
//   - Exact match (case-insensitive, e.g. "gitlab-fleet-governor")
//   - Universal wildcards: "*" or "all" matches any product
//   - Suite bundles: "divmora-suite" or "suite" (case-insensitive) matches all Divmora products
//   - Comma or semicolon-separated multi-product lists (e.g. "gitlab-fleet-governor, otel-aws-log-processor")
//   - Glob pattern matching: e.g. "gitlab-*" or "otel-*" (via path.Match)
func (c *Claims) IsValidForProduct(expectedProduct string) bool {
	if expectedProduct == "" {
		return true
	}
	expectedLower := strings.ToLower(strings.TrimSpace(expectedProduct))
	prodLower := strings.ToLower(strings.TrimSpace(c.Product))

	if prodLower == "" {
		return false
	}

	// 1. Universal wildcards & suite bundles
	if prodLower == "*" || prodLower == "all" || prodLower == "divmora-suite" || prodLower == "suite" {
		return true
	}

	// 2. Exact match
	if prodLower == expectedLower {
		return true
	}

	// 3. Comma or semicolon-separated multi-product list
	if strings.ContainsAny(prodLower, ",;") {
		for _, item := range strings.FieldsFunc(prodLower, func(r rune) bool {
			return r == ',' || r == ';'
		}) {
			item = strings.TrimSpace(item)
			if item == "*" || item == "all" || item == "divmora-suite" || item == "suite" || item == expectedLower {
				return true
			}
			if strings.ContainsAny(item, "*?[") {
				if matched, _ := path.Match(item, expectedLower); matched {
					return true
				}
			}
		}
	}

	// 4. Glob pattern match (e.g. "gitlab-*" or "divmora-*")
	if strings.ContainsAny(prodLower, "*?[") {
		if matched, _ := path.Match(prodLower, expectedLower); matched {
			return true
		}
	}

	return false
}

// HasFeature returns true if the specified feature flag is enabled in the license.
// It supports:
//   - Exact match (case-insensitive, e.g. "ha" matches "HA")
//   - Wildcards: "*" or "all" (case-insensitive) in Claims.Features matches any feature
//   - Glob pattern matching: e.g. "audit:*", "s3_*", or "report:*" (via path.Match)
func (c *Claims) HasFeature(feature string) bool {
	featureLower := strings.ToLower(feature)
	for _, f := range c.Features {
		fLower := strings.ToLower(f)
		if fLower == "*" || fLower == "all" {
			return true
		}
		if fLower == featureLower {
			return true
		}
		if strings.ContainsAny(fLower, "*?[") {
			if matchFeaturePattern(fLower, featureLower) {
				return true
			}
		}
	}
	return false
}

// matchFeaturePattern tests whether name matches pattern, allowing wildcards across separators.
func matchFeaturePattern(pattern, name string) bool {
	if matched, _ := path.Match(pattern, name); matched {
		return true
	}
	if strings.Contains(name, "/") || strings.Contains(pattern, "/") {
		safePattern := strings.ReplaceAll(pattern, "/", "::")
		safeName := strings.ReplaceAll(name, "/", "::")
		if matched, _ := path.Match(safePattern, safeName); matched {
			return true
		}
	}
	return false
}

// AssertFeature returns nil if the feature is enabled, or ErrFeatureNotEntitled if not.
func (c *Claims) AssertFeature(feature string) error {
	if c.HasFeature(feature) {
		return nil
	}
	return &FeatureNotEntitledError{Feature: feature}
}

// GetLimit returns the quota limit for a given key, if defined.
func (c *Claims) GetLimit(name string) (int64, bool) {
	if c.Limits == nil {
		return 0, false
	}
	// Try exact match first
	if val, ok := c.Limits[name]; ok {
		return val, true
	}
	// Case-insensitive fallback
	for k, val := range c.Limits {
		if strings.EqualFold(k, name) {
			return val, true
		}
	}
	return 0, false
}

// CheckLimit checks if currentUsage is within the allowed limit for the given key.
// If the limit is not found, or is set to -1 (unlimited), it returns nil.
// If currentUsage exceeds the limit, it returns *LimitExceededError.
func (c *Claims) CheckLimit(name string, currentUsage int64) error {
	limit, exists := c.GetLimit(name)
	if !exists || limit == -1 {
		return nil
	}
	if currentUsage > limit {
		return &LimitExceededError{
			LimitName: name,
			Current:   currentUsage,
			Allowed:   limit,
		}
	}
	return nil
}

// IsTrial reports whether the license is a trial plan.
func (c *Claims) IsTrial() bool {
	return strings.EqualFold(c.Plan, "trial")
}

// GetMetadata retrieves a custom metadata value by key (case-insensitive fallback).
func (c *Claims) GetMetadata(key string) (string, bool) {
	if c.Metadata == nil {
		return "", false
	}
	if val, ok := c.Metadata[key]; ok {
		return val, true
	}
	for k, val := range c.Metadata {
		if strings.EqualFold(k, key) {
			return val, true
		}
	}
	return "", false
}

// IsBoundToFingerprint reports whether the license is node-locked to a specific fingerprint.
func (c *Claims) IsBoundToFingerprint() bool {
	return c.Fingerprint != ""
}

// MatchesFingerprint checks if the license fingerprint matches the provided host fingerprint.
// Floating licenses (Fingerprint == "") return true for any host.
// Node-locked licenses return true only if hostFingerprint matches case-insensitively.
func (c *Claims) MatchesFingerprint(hostFingerprint string) bool {
	if c.Fingerprint == "" {
		return true
	}
	if hostFingerprint == "" {
		return false
	}
	return strings.EqualFold(c.Fingerprint, hostFingerprint)
}

// IsEnvironmentAllowed reports whether the target deployment environment is authorized.
// If neither Scope.Environments nor Claims.Environment is defined, any environment is permitted.
func (c *Claims) IsEnvironmentAllowed(env string) bool {
	if c.Scope != nil && len(c.Scope.Environments) > 0 {
		return matchesScopeSlice(c.Scope.Environments, env)
	}
	if c.Environment != "" {
		return matchesScopeSlice([]string{c.Environment}, env)
	}
	return true
}

// IsAccountAllowed reports whether the target cloud tenant or account ID (e.g. AWS Account ID) is authorized.
// If Scope.Accounts is not defined or empty, all accounts are authorized.
func (c *Claims) IsAccountAllowed(account string) bool {
	if c.Scope == nil || len(c.Scope.Accounts) == 0 {
		return true
	}
	return matchesScopeSlice(c.Scope.Accounts, account)
}

// IsRegionAllowed reports whether the target geographic/cloud region (e.g. "us-east-1") is authorized.
// If Scope.Regions is not defined or empty, all regions are authorized.
func (c *Claims) IsRegionAllowed(region string) bool {
	if c.Scope == nil || len(c.Scope.Regions) == 0 {
		return true
	}
	return matchesScopeSlice(c.Scope.Regions, region)
}

// IsClusterAllowed reports whether the target cluster ID/ARN is authorized.
// If Scope.Clusters is not defined or empty, all clusters are authorized.
func (c *Claims) IsClusterAllowed(cluster string) bool {
	if c.Scope == nil || len(c.Scope.Clusters) == 0 {
		return true
	}
	return matchesScopeSlice(c.Scope.Clusters, cluster)
}

// IsNamespaceAllowed reports whether the target project/group hierarchy (e.g. "gitlab.com/acme/*") is authorized.
// If Scope.Namespaces is not defined or empty, all namespaces are authorized.
func (c *Claims) IsNamespaceAllowed(namespace string) bool {
	if c.Scope == nil || len(c.Scope.Namespaces) == 0 {
		return true
	}
	return matchesScopeSlice(c.Scope.Namespaces, namespace)
}

// IsHostAllowed reports whether the target hostname, FQDN, or domain pattern is authorized.
// If Scope.Hosts is not defined or empty, all hosts are authorized.
func (c *Claims) IsHostAllowed(host string) bool {
	if c.Scope == nil || len(c.Scope.Hosts) == 0 {
		return true
	}
	return matchesScopeSlice(c.Scope.Hosts, host)
}

// IsInScope checks whether target is permitted under the given dimension name.
// Supported standard dimensions: "environments", "accounts", "regions", "clusters", "namespaces", "hosts",
// or any key in Scope.Custom.
func (c *Claims) IsInScope(dimension string, target string) bool {
	dimLower := strings.ToLower(strings.TrimSpace(dimension))
	switch dimLower {
	case "environments", "environment", "env":
		return c.IsEnvironmentAllowed(target)
	case "accounts", "account":
		return c.IsAccountAllowed(target)
	case "regions", "region":
		return c.IsRegionAllowed(target)
	case "clusters", "cluster":
		return c.IsClusterAllowed(target)
	case "namespaces", "namespace", "groups", "group":
		return c.IsNamespaceAllowed(target)
	case "hosts", "host", "domain", "domains":
		return c.IsHostAllowed(target)
	default:
		if c.Scope != nil && c.Scope.Custom != nil {
			for k, allowed := range c.Scope.Custom {
				if strings.EqualFold(k, dimension) {
					return matchesScopeSlice(allowed, target)
				}
			}
		}
		return true
	}
}

// AssertScope asserts that target is permitted under dimension, returning ScopeMismatchError if not.
func (c *Claims) AssertScope(dimension string, target string) error {
	if c.IsInScope(dimension, target) {
		return nil
	}
	var allowed []string
	if c.Scope != nil {
		switch strings.ToLower(strings.TrimSpace(dimension)) {
		case "environments", "environment", "env":
			allowed = c.Scope.Environments
		case "accounts", "account":
			allowed = c.Scope.Accounts
		case "regions", "region":
			allowed = c.Scope.Regions
		case "clusters", "cluster":
			allowed = c.Scope.Clusters
		case "namespaces", "namespace", "groups", "group":
			allowed = c.Scope.Namespaces
		case "hosts", "host", "domain", "domains":
			allowed = c.Scope.Hosts
		default:
			if c.Scope.Custom != nil {
				for k, v := range c.Scope.Custom {
					if strings.EqualFold(k, dimension) {
						allowed = v
						break
					}
				}
			}
		}
	}
	if len(allowed) == 0 && c.Environment != "" && strings.Contains(strings.ToLower(dimension), "env") {
		allowed = []string{c.Environment}
	}
	return &ScopeMismatchError{
		Dimension: dimension,
		Allowed:   allowed,
		Target:    target,
	}
}

// matchesScopeSlice evaluates whether target matches any pattern in allowed slice.
// If allowed is empty, returns true (unrestricted).
// If target is empty, returns false.
func matchesScopeSlice(allowed []string, target string) bool {
	if len(allowed) == 0 {
		return true
	}
	targetTrimmed := strings.TrimSpace(target)
	if targetTrimmed == "" {
		return false
	}
	targetLower := strings.ToLower(targetTrimmed)

	for _, entry := range allowed {
		entryTrimmed := strings.TrimSpace(entry)
		entryLower := strings.ToLower(entryTrimmed)
		if entryLower == "*" || entryLower == "all" {
			return true
		}
		if entryLower == targetLower {
			return true
		}
		if strings.ContainsAny(entryLower, "*?[") {
			if matchFeaturePattern(entryLower, targetLower) {
				return true
			}
		}
	}
	return false
}
