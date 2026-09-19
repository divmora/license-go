package license

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/divmora/license-go/internal/helpers"
	"github.com/divmora/license-go/internal/schema"
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

// IsEnvironmentAllowed reports whether the target deployment environment is authorized by Scope.Environments.
func (s *Scope) IsEnvironmentAllowed(env string) bool {
	if s == nil || len(s.Environments) == 0 {
		return true
	}
	return matchesScopeSlice(s.Environments, env)
}

// IsAccountAllowed reports whether the target cloud tenant or account ID is authorized by Scope.Accounts.
func (s *Scope) IsAccountAllowed(account string) bool {
	if s == nil || len(s.Accounts) == 0 {
		return true
	}
	return matchesScopeSlice(s.Accounts, account)
}

// IsRegionAllowed reports whether the target geographic/cloud region is authorized by Scope.Regions.
func (s *Scope) IsRegionAllowed(region string) bool {
	if s == nil || len(s.Regions) == 0 {
		return true
	}
	return matchesScopeSlice(s.Regions, region)
}

// IsClusterAllowed reports whether the target cluster ID/ARN is authorized by Scope.Clusters.
func (s *Scope) IsClusterAllowed(cluster string) bool {
	if s == nil || len(s.Clusters) == 0 {
		return true
	}
	return matchesScopeSlice(s.Clusters, cluster)
}

// IsNamespaceAllowed reports whether the target project/group hierarchy is authorized by Scope.Namespaces.
// Both the target and scope patterns are normalized via NormalizeNamespace.
// Hierarchical group tree matching is supported: patterns like "devops" or "devops/*"
// authorize root group "devops" as well as all descendant sub-groups and repositories (e.g. "devops/backend/service").
// If Scope.Namespaces is not defined or empty, all namespaces are authorized.
func (s *Scope) IsNamespaceAllowed(namespace string) bool {
	if s == nil || len(s.Namespaces) == 0 {
		return true
	}
	return matchesNamespaceScope(s.Namespaces, namespace)
}

// IsHostAllowed reports whether the target hostname, FQDN, domain, or URL is authorized by Scope.Hosts.
// Both the target and scope patterns are normalized via NormalizeHost.
// Wildcard domain patterns (e.g. "*.acme.corp") authorize both subdomains ("gitlab.acme.corp")
// and the apex domain ("acme.corp").
// If Scope.Hosts is not defined or empty, all hosts are authorized.
func (s *Scope) IsHostAllowed(host string) bool {
	if s == nil || len(s.Hosts) == 0 {
		return true
	}
	return matchesHostScope(s.Hosts, host)
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

	// MaxVersion defines the maximum authorized software version (e.g., "1.*", "2.4.0", "<=2.5.0").
	// Constrains perpetual licenses from running unpurchased major upgrades.
	MaxVersion string `json:"max_version,omitempty"`

	// AllowedVersions defines an explicit allowlist of version patterns (e.g. ["1.*", "2.0.*"]).
	AllowedVersions []string `json:"allowed_versions,omitempty"`

	// MaintenanceExpiresAt specifies the maintenance/support update cutoff date.
	// For perpetual licenses, binaries built/released on or before this date are entitled to run forever.
	// Binaries built after this date require a maintenance renewal.
	MaintenanceExpiresAt time.Time `json:"maintenance_expires_at,omitempty"`

	// Metadata contains arbitrary key-value custom properties.
	Metadata map[string]string `json:"metadata,omitempty"`

	// tierFeatures is an optional runtime mapping of plan names to entitled features,
	// used to dynamically evaluate features based on plan tier. Not serialized in JSON.
	tierFeatures TierFeatures `json:"-"`
}

// TierFeatures defines a mapping of subscription plan/tier names (case-insensitive) to their entitled feature flags.
// Feature lists support exact feature names, wildcards ("*" or "all"), and glob patterns (e.g. "audit.*").
type TierFeatures map[string][]string

// isValidEmail validates an email address string against standard email format requirements.
func isValidEmail(email string) bool {
	return helpers.IsValidEmail(email)
}

// ValidateClaimsSchema validates the Claims struct against the DIV1 claims schema constraints
// specified in SPEC.md §4.1.
// Returns a typed error wrapping ErrInvalidLicenseFormat on violation.
func (c *Claims) ValidateClaimsSchema() error {
	if c.ID == "" {
		return fmt.Errorf("%w: claims.id is required", ErrInvalidLicenseFormat)
	}
	if c.Customer.Name == "" {
		return fmt.Errorf("%w: claims.customer.name is required", ErrInvalidLicenseFormat)
	}
	if c.Product == "" {
		return fmt.Errorf("%w: claims.product is required", ErrInvalidLicenseFormat)
	}
	if c.Plan == "" {
		return fmt.Errorf("%w: claims.plan is required", ErrInvalidLicenseFormat)
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("%w: claims.issued_at is required", ErrInvalidLicenseFormat)
	}
	if c.Customer.Email != "" && !isValidEmail(c.Customer.Email) {
		return fmt.Errorf("%w: claims.customer.email format is invalid: %q", ErrInvalidLicenseFormat, c.Customer.Email)
	}
	return nil
}

// ValidateClaimsPayloadJSON validates the raw JSON claims bytes against the DIV1 JSON schema constraints
// specified in SPEC.md §4.1.
// Validates required fields, object structures, email format, and limit integer type constraints.
// Returns a typed error wrapping ErrInvalidLicenseFormat on violation.
func ValidateClaimsPayloadJSON(data []byte) error {
	return schema.ValidateClaimsPayloadJSON(data)
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

// IsInGracePeriodAt reports whether the license is in grace period at reference time t,
// optionally accounting for clock skew tolerance.
func (c *Claims) IsInGracePeriodAt(t time.Time, skew ...time.Duration) bool {
	if c.IsPerpetual() || c.GracePeriodDays <= 0 {
		return false
	}
	var clockSkew time.Duration
	if len(skew) > 0 && skew[0] > 0 {
		clockSkew = skew[0]
	}
	effectiveExpiresAt := c.ExpiresAt.Add(clockSkew)
	cutoff := c.EffectiveExpiration().Add(clockSkew)
	return t.After(effectiveExpiresAt) && (t.Before(cutoff) || t.Equal(cutoff))
}

// GraceDaysRemaining returns the number of full grace period days remaining if the license
// is currently operating in its grace period. If not in grace period, it returns 0.
func (c *Claims) GraceDaysRemaining() int {
	return c.GraceDaysRemainingAt(time.Now())
}

// GraceDaysRemainingAt returns the number of full grace period days remaining at reference time t,
// optionally accounting for clock skew tolerance.
func (c *Claims) GraceDaysRemainingAt(t time.Time, skew ...time.Duration) int {
	if !c.IsInGracePeriodAt(t, skew...) {
		return 0
	}
	var clockSkew time.Duration
	if len(skew) > 0 && skew[0] > 0 {
		clockSkew = skew[0]
	}
	diff := c.EffectiveExpiration().Add(clockSkew).Sub(t)
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

// IsExpiredAt reports whether the license has passed its initial expiration date at time t,
// optionally accounting for clock skew tolerance.
func (c *Claims) IsExpiredAt(t time.Time, skew ...time.Duration) bool {
	if c.IsPerpetual() {
		return false
	}
	var clockSkew time.Duration
	if len(skew) > 0 && skew[0] > 0 {
		clockSkew = skew[0]
	}
	return t.After(c.ExpiresAt.Add(clockSkew))
}

// IsActive reports whether the license is currently operational (valid NotBefore and before EffectiveExpiration).
func (c *Claims) IsActive() bool {
	return c.IsActiveAt(time.Now())
}

// IsActiveAt reports whether the license is operational at time t,
// optionally accounting for clock skew tolerance.
func (c *Claims) IsActiveAt(t time.Time, skew ...time.Duration) bool {
	var clockSkew time.Duration
	if len(skew) > 0 && skew[0] > 0 {
		clockSkew = skew[0]
	}
	if !c.NotBefore.IsZero() {
		effectiveNotBefore := c.NotBefore.Add(-clockSkew)
		if t.Before(effectiveNotBefore) {
			return false
		}
	}
	if c.IsPerpetual() {
		return true
	}
	return !c.IsExpiredAt(t, clockSkew) || c.IsInGracePeriodAt(t, clockSkew)
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
	// StatusRevoked indicates the license has been invalidated by a Certificate Revocation List (CRL).
	StatusRevoked Status = "REVOKED"
)

// Status returns the operational lifecycle Status of the license at the current time.
func (c *Claims) Status() Status {
	return c.StatusAt(time.Now())
}

// StatusWithTolerance returns the operational lifecycle Status of the license at reference time t,
// incorporating clock skew tolerance and validator-level extra grace period.
func (c *Claims) StatusWithTolerance(t time.Time, clockSkew time.Duration, extraGrace time.Duration) Status {
	if !c.NotBefore.IsZero() {
		effectiveNotBefore := c.NotBefore.Add(-clockSkew)
		if t.Before(effectiveNotBefore) {
			return StatusNotYetValid
		}
	}
	if c.IsPerpetual() {
		return StatusActive
	}

	effectiveGrace := extraGrace
	if c.GracePeriodDays > 0 {
		claimGrace := time.Duration(c.GracePeriodDays) * 24 * time.Hour
		if claimGrace > effectiveGrace {
			effectiveGrace = claimGrace
		}
	}

	if effectiveGrace > 0 {
		effectiveExpiresAt := c.ExpiresAt.Add(clockSkew)
		cutoff := c.ExpiresAt.Add(effectiveGrace).Add(clockSkew)
		if t.After(effectiveExpiresAt) && (t.Before(cutoff) || t.Equal(cutoff)) {
			return StatusGracePeriod
		}
	}

	effectiveExpiry := c.ExpiresAt.Add(clockSkew).Add(effectiveGrace)
	if t.After(effectiveExpiry) {
		return StatusExpired
	}
	return StatusActive
}

// StatusAt returns the operational lifecycle Status of the license at reference time t,
// optionally accounting for clock skew tolerance.
func (c *Claims) StatusAt(t time.Time, skew ...time.Duration) Status {
	var clockSkew time.Duration
	if len(skew) > 0 && skew[0] > 0 {
		clockSkew = skew[0]
	}
	return c.StatusWithTolerance(t, clockSkew, 0)
}

// DaysRemaining returns the number of full days remaining before expiration.
// If the license is perpetual, it returns -1.
// If the license is already expired, it returns 0.
func (c *Claims) DaysRemaining() int {
	return c.DaysRemainingAt(time.Now())
}

// DaysRemainingAt returns the number of full days remaining before expiration at reference time t.
// If the license is perpetual, it returns -1.
// If the license is already expired at reference time t, it returns 0.
func (c *Claims) DaysRemainingAt(t time.Time) int {
	if c.IsPerpetual() {
		return -1
	}
	diff := c.ExpiresAt.Sub(t)
	if diff <= 0 {
		return 0
	}
	return int(diff.Hours() / 24)
}

// StatusMessage returns a standardized human-readable description of the license status at the current time.
func (c *Claims) StatusMessage() string {
	return c.StatusMessageAt(time.Now())
}

// StatusMessageAt returns a standardized human-readable description of the license status at reference time t,
// optionally accounting for clock skew tolerance.
// Descriptions cover:
//   - Perpetual licenses: "Perpetual license (does not expire)"
//   - Future NotBefore: "License is not yet valid (valid starting <NotBefore>)"
//   - Grace period: "Operating in grace period (<N> grace days remaining until <cutoff>, expired on <ExpiresAt>)"
//   - Expired: "License expired on <ExpiresAt>" or "License expired on <ExpiresAt> (grace period ended <cutoff>)"
//   - Active: "Active (<N> days remaining, expires <ExpiresAt>)" (or "Active (1 day remaining, ...)" or "Active (less than 1 day remaining, ...)")
func (c *Claims) StatusMessageAt(t time.Time, skew ...time.Duration) string {
	if c == nil {
		return "No license claims"
	}
	var clockSkew time.Duration
	if len(skew) > 0 && skew[0] > 0 {
		clockSkew = skew[0]
	}
	if c.IsPerpetual() {
		return "Perpetual license (does not expire)"
	}
	if !c.NotBefore.IsZero() {
		effectiveNotBefore := c.NotBefore.Add(-clockSkew)
		if t.Before(effectiveNotBefore) {
			return fmt.Sprintf("License is not yet valid (valid starting %s)", c.NotBefore.Format(time.RFC3339))
		}
	}
	if c.IsInGracePeriodAt(t, clockSkew) {
		graceDays := c.GraceDaysRemainingAt(t, clockSkew)
		cutoffStr := c.EffectiveExpiration().Format(time.RFC3339)
		expiresStr := c.ExpiresAt.Format(time.RFC3339)
		if graceDays == 1 {
			return fmt.Sprintf("Operating in grace period (1 grace day remaining until %s, expired on %s)", cutoffStr, expiresStr)
		}
		if graceDays == 0 {
			return fmt.Sprintf("Operating in grace period (less than 1 grace day remaining until %s, expired on %s)", cutoffStr, expiresStr)
		}
		return fmt.Sprintf("Operating in grace period (%d grace days remaining until %s, expired on %s)", graceDays, cutoffStr, expiresStr)
	}
	if c.IsExpiredAt(t, clockSkew) {
		expiresStr := c.ExpiresAt.Format(time.RFC3339)
		if c.GracePeriodDays > 0 {
			cutoffStr := c.EffectiveExpiration().Format(time.RFC3339)
			return fmt.Sprintf("License expired on %s (grace period ended %s)", expiresStr, cutoffStr)
		}
		return fmt.Sprintf("License expired on %s", expiresStr)
	}
	days := c.DaysRemainingAt(t)
	expiresStr := c.ExpiresAt.Format(time.RFC3339)
	if days > 1 {
		return fmt.Sprintf("Active (%d days remaining, expires %s)", days, expiresStr)
	}
	if days == 1 {
		return fmt.Sprintf("Active (1 day remaining, expires %s)", expiresStr)
	}
	return fmt.Sprintf("Active (less than 1 day remaining, expires %s)", expiresStr)
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

// WithTierFeatures returns the Claims instance configured with a tier feature matrix.
func (c *Claims) WithTierFeatures(tiers TierFeatures) *Claims {
	if c != nil {
		c.tierFeatures = tiers
	}
	return c
}

// SetTierFeatures attaches a tier feature matrix to this Claims instance.
func (c *Claims) SetTierFeatures(tiers TierFeatures) {
	if c != nil {
		c.tierFeatures = tiers
	}
}

// TierFeatures returns the currently attached tier feature matrix, if any.
func (c *Claims) TierFeatures() TierFeatures {
	if c == nil {
		return nil
	}
	return c.tierFeatures
}

// HasFeature returns true if the specified feature flag is enabled in the license.
// If a TierFeatures matrix is attached to Claims, it evaluates the customer's Plan tier first.
// It also evaluates explicit features in Claims.Features (including exact, glob, and "*" wildcards).
// It supports:
//   - Exact match (case-insensitive, e.g. "ha" matches "HA")
//   - Wildcards: "*" or "all" (case-insensitive) in Claims.Features or tier definition
//   - Glob pattern matching: e.g. "audit:*", "s3_*", or "report:*" (via path.Match)
func (c *Claims) HasFeature(feature string) bool {
	if c == nil {
		return false
	}
	featureLower := strings.ToLower(feature)
	if len(c.tierFeatures) > 0 {
		return c.HasFeatureWithTiers(featureLower, c.tierFeatures)
	}
	return c.hasFeatureInList(featureLower, c.Features)
}

// HasFeatureWithTiers reports whether the specified feature is enabled, evaluating:
//  1. The tier feature matrix for Claims.Plan (case-insensitive plan name match)
//  2. Explicit features granted in Claims.Features (including exact, glob, and "*" wildcards)
func (c *Claims) HasFeatureWithTiers(feature string, tierMap TierFeatures) bool {
	if c == nil {
		return false
	}
	featureLower := strings.ToLower(feature)

	// 1. Check plan tier matrix
	if len(tierMap) > 0 && c.Plan != "" {
		for planName, features := range tierMap {
			if strings.EqualFold(planName, c.Plan) {
				if c.hasFeatureInList(featureLower, features) {
					return true
				}
				break
			}
		}
	}

	// 2. Check explicit license features (add-ons and custom overrides)
	return c.hasFeatureInList(featureLower, c.Features)
}

func (c *Claims) hasFeatureInList(feature string, list []string) bool {
	featureLower := strings.ToLower(feature)
	for _, f := range list {
		fLower := strings.ToLower(f)
		if fLower == "*" || fLower == "all" || fLower == featureLower {
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

// EffectiveFeatures returns the consolidated list of all entitled features,
// combining the tier features configured for Claims.Plan with any explicit Claims.Features.
// Deduplicates features while preserving definition order.
func (c *Claims) EffectiveFeatures() []string {
	if c == nil {
		return nil
	}
	return c.EffectiveFeaturesWithTiers(c.tierFeatures)
}

// EffectiveFeaturesWithTiers returns the consolidated list of all entitled features
// evaluated against the provided tier feature matrix and explicit Claims.Features.
func (c *Claims) EffectiveFeaturesWithTiers(tierMap TierFeatures) []string {
	if c == nil {
		return nil
	}
	var combined []string
	seen := make(map[string]bool)

	add := func(f string) {
		fTrimmed := strings.TrimSpace(f)
		fLower := strings.ToLower(fTrimmed)
		if fTrimmed != "" && !seen[fLower] {
			seen[fLower] = true
			combined = append(combined, fTrimmed)
		}
	}

	if len(tierMap) > 0 && c.Plan != "" {
		for planName, features := range tierMap {
			if strings.EqualFold(planName, c.Plan) {
				for _, f := range features {
					add(f)
				}
				break
			}
		}
	}

	for _, f := range c.Features {
		add(f)
	}

	return combined
}

// splitPathSegments splits a slash-delimited path into non-empty segments.
func splitPathSegments(s string) []string {
	parts := strings.Split(s, "/")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

// matchSegments matches a slice of pattern segments against a slice of candidate segments.
// Individual segments match using path.Match (where '*' matches any sequence of non-'/' characters).
// The recursive wildcard segment '**' matches zero or more directory/hierarchy path segments.
func matchSegments(pParts, nParts []string) bool {
	for len(pParts) > 0 {
		if pParts[0] == "**" {
			// Collapse consecutive "**"
			for len(pParts) > 1 && pParts[1] == "**" {
				pParts = pParts[1:]
			}
			// If "**" is the terminal pattern segment, it matches all remaining candidate segments (including zero)
			if len(pParts) == 1 {
				return true
			}
			// Try matching the remainder of pattern against all possible sub-slices of nParts
			for i := 0; i <= len(nParts); i++ {
				if matchSegments(pParts[1:], nParts[i:]) {
					return true
				}
			}
			return false
		}

		// Pattern segment is not "**", so it must match exactly one candidate segment
		if len(nParts) == 0 {
			return false
		}

		matched, err := path.Match(pParts[0], nParts[0])
		if err != nil || !matched {
			return false
		}

		pParts = pParts[1:]
		nParts = nParts[1:]
	}

	return len(nParts) == 0
}

// matchFeaturePattern tests whether candidate matches pattern.
// Wildcards ('*', '?', character classes) match only within a single path segment and never across '/'.
// The recursive wildcard ('**') matches across path segments.
func matchFeaturePattern(pattern, name string) bool {
	if pattern == "*" || pattern == "**" || pattern == "all" {
		return true
	}
	if pattern == name {
		return true
	}

	// Fast path: if neither string contains "/" and pattern does not contain "**", use path.Match directly.
	if !strings.Contains(pattern, "/") && !strings.Contains(name, "/") && !strings.Contains(pattern, "**") {
		matched, _ := path.Match(pattern, name)
		return matched
	}

	pParts := splitPathSegments(pattern)
	nParts := splitPathSegments(name)
	return matchSegments(pParts, nParts)
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

// constantTimeFingerprintMatch performs a constant-time case-insensitive string comparison
// between two fingerprints to prevent timing side-channel attacks.
func constantTimeFingerprintMatch(a, b string) bool {
	return helpers.ConstantTimeFingerprintMatch(a, b)
}

// MatchesFingerprint checks if the license fingerprint matches the provided host fingerprint.
// Floating licenses (Fingerprint == "") return true for any host.
// Node-locked licenses return true only if hostFingerprint matches case-insensitively using constant-time comparison.
func (c *Claims) MatchesFingerprint(hostFingerprint string) bool {
	if c.Fingerprint == "" {
		return true
	}
	if hostFingerprint == "" {
		return false
	}
	return constantTimeFingerprintMatch(c.Fingerprint, hostFingerprint)
}

// IsEnvironmentAllowed reports whether the target deployment environment is authorized.
// If neither Scope.Environments nor Claims.Environment is defined, any environment is permitted.
func (c *Claims) IsEnvironmentAllowed(env string) bool {
	if c.Scope != nil && len(c.Scope.Environments) > 0 {
		return c.Scope.IsEnvironmentAllowed(env)
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
	return c.Scope.IsAccountAllowed(account)
}

// IsRegionAllowed reports whether the target geographic/cloud region (e.g. "us-east-1") is authorized.
// If Scope.Regions is not defined or empty, all regions are authorized.
func (c *Claims) IsRegionAllowed(region string) bool {
	if c.Scope == nil || len(c.Scope.Regions) == 0 {
		return true
	}
	return c.Scope.IsRegionAllowed(region)
}

// IsClusterAllowed reports whether the target cluster ID/ARN is authorized.
// If Scope.Clusters is not defined or empty, all clusters are authorized.
func (c *Claims) IsClusterAllowed(cluster string) bool {
	if c.Scope == nil || len(c.Scope.Clusters) == 0 {
		return true
	}
	return c.Scope.IsClusterAllowed(cluster)
}

// IsNamespaceAllowed reports whether the target project/group hierarchy (e.g. "gitlab.com/acme/*", "devops") is authorized.
// Both the target and scope patterns are normalized via NormalizeNamespace.
// Hierarchical group tree matching is supported: patterns like "devops" or "devops/*"
// authorize root group "devops" as well as all descendant sub-groups and repositories (e.g. "devops/backend/service").
// If Scope.Namespaces is not defined or empty, all namespaces are authorized.
func (c *Claims) IsNamespaceAllowed(namespace string) bool {
	if c.Scope == nil || len(c.Scope.Namespaces) == 0 {
		return true
	}
	return c.Scope.IsNamespaceAllowed(namespace)
}

// IsHostAllowed reports whether the target hostname, FQDN, domain, or URL is authorized.
// Both the target and scope patterns are normalized via NormalizeHost.
// Wildcard domain patterns (e.g. "*.acme.corp") authorize both subdomains ("gitlab.acme.corp")
// and the apex domain ("acme.corp").
// If Scope.Hosts is not defined or empty, all hosts are authorized.
func (c *Claims) IsHostAllowed(host string) bool {
	if c.Scope == nil || len(c.Scope.Hosts) == 0 {
		return true
	}
	return c.Scope.IsHostAllowed(host)
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

// HasScopeDimension reports whether a specific scope dimension is explicitly defined and non-empty in Claims.
func (c *Claims) HasScopeDimension(dimension string) bool {
	dimLower := strings.ToLower(strings.TrimSpace(dimension))
	switch dimLower {
	case "environments", "environment", "env":
		return (c.Scope != nil && len(c.Scope.Environments) > 0) || strings.TrimSpace(c.Environment) != ""
	case "accounts", "account":
		return c.Scope != nil && len(c.Scope.Accounts) > 0
	case "regions", "region":
		return c.Scope != nil && len(c.Scope.Regions) > 0
	case "clusters", "cluster":
		return c.Scope != nil && len(c.Scope.Clusters) > 0
	case "namespaces", "namespace", "groups", "group":
		return c.Scope != nil && len(c.Scope.Namespaces) > 0
	case "hosts", "host", "domain", "domains":
		return c.Scope != nil && len(c.Scope.Hosts) > 0
	default:
		if c.Scope != nil && c.Scope.Custom != nil {
			for k, allowed := range c.Scope.Custom {
				if strings.EqualFold(k, dimension) {
					return len(allowed) > 0
				}
			}
		}
		return false
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

// NormalizeHost extracts and normalizes a clean hostname, FQDN, or IP address from a URL,
// host:port string, or raw hostname.
// It trims whitespace, strips schemes (e.g. "http://", "https://", "grpc://", "//"), user credentials ("user:pass@"),
// ports (e.g. ":8080"), trailing paths (e.g. "/api/v1"), query parameters, and fragments,
// and lowercases the result.
func NormalizeHost(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return ""
	}

	// 1. Strip scheme (e.g. "http://", "https://", "grpc://", or protocol-relative "//")
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	} else {
		s = strings.TrimPrefix(s, "//")
	}

	// 2. Strip path, query params, and fragment (everything from the first '/', '?', or '#')
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}

	// 3. Strip user credentials (everything before the last '@')
	if idx := strings.LastIndex(s, "@"); idx != -1 {
		s = s[idx+1:]
	}

	// 4. Handle host and port
	if strings.HasPrefix(s, "[") {
		// IPv6 bracketed address: "[::1]:8080" or "[2001:db8::1]"
		if closeBracket := strings.Index(s, "]"); closeBracket != -1 {
			s = s[1:closeBracket]
		}
	} else if colonIdx := strings.LastIndex(s, ":"); colonIdx != -1 {
		// If there is exactly one colon, it separates host and port (e.g. "gitlab.acme.corp:8080", "127.0.0.1:9090")
		// (Multiple colons without brackets indicate an unbracketed IPv6 literal like "::1" or "2001:db8::1")
		if strings.Count(s, ":") == 1 {
			s = s[:colonIdx]
		}
	}

	// 5. Lowercase, trim whitespace and trailing dot
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

// matchesHostPattern checks whether a target host matches an allowed host pattern.
// It supports:
//   - Wildcards: "*" or "all" matches any host.
//   - Exact match: "gitlab.acme.corp" matches "gitlab.acme.corp".
//   - Wildcard domain & Apex matching: "*.acme.corp" matches both subdomains ("gitlab.acme.corp",
//     "runner.dev.acme.corp") and the apex domain ("acme.corp").
//   - Leading dot domain matching: ".acme.corp" matches both "acme.corp" and subdomains.
//   - Standard glob patterns: "runner-*.acme.corp" or "srv[0-9].acme.corp".
func matchesHostPattern(pattern, target string) bool {
	p := NormalizeHost(pattern)
	t := NormalizeHost(target)
	if p == "" || t == "" {
		return false
	}

	if p == "*" || p == "all" {
		return true
	}

	if p == t {
		return true
	}

	// Wildcard domain matching: "*.domain.tld"
	if strings.HasPrefix(p, "*.") {
		apex := strings.TrimPrefix(p, "*.")
		// 1. Apex domain match: target is "acme.corp"
		if t == apex {
			return true
		}
		// 2. Subdomain match: target is "sub.acme.corp" or "a.b.acme.corp"
		if strings.HasSuffix(t, "."+apex) {
			return true
		}
	}

	// Leading dot domain matching: ".domain.tld"
	if strings.HasPrefix(p, ".") {
		apex := strings.TrimPrefix(p, ".")
		if t == apex || strings.HasSuffix(t, "."+apex) {
			return true
		}
	}

	// General glob matching (e.g. "runner-*.acme.corp", "srv[1-9].internal")
	if strings.ContainsAny(p, "*?[") {
		if matched, _ := path.Match(p, t); matched {
			return true
		}
	}

	return false
}

// matchesHostScope evaluates whether target matches any host pattern in allowed.
// If allowed is empty, returns true (unrestricted).
// If target is empty, returns false.
func matchesHostScope(allowed []string, target string) bool {
	if len(allowed) == 0 {
		return true
	}
	normTarget := NormalizeHost(target)
	if normTarget == "" {
		return false
	}

	for _, entry := range allowed {
		if matchesHostPattern(entry, normTarget) {
			return true
		}
	}
	return false
}

// NormalizeNamespace extracts and normalizes a clean group, project, repository, or namespace path.
// It trims whitespace, strips query parameters and URL fragments, removes URL schemes
// (e.g. "https://", "http://", "git://", "ssh://", or protocol-relative "//"),
// converts SCP-style git URLs ("git@gitlab.com:group/subgroup/repo.git" -> "gitlab.com/group/subgroup/repo"),
// strips user credentials ("user:pass@"), strips port from host if present (e.g. ":8443"),
// removes trailing ".git" extensions, cleans redundant slashes via path.Clean,
// strips leading/trailing slashes, and lowercases the result.
func NormalizeNamespace(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	// 1. Strip fragment and query params (e.g. "?ref=main#readme")
	if idx := strings.IndexAny(s, "?#"); idx != -1 {
		s = s[:idx]
	}

	// 2. Handle SCP-style git URL: "git@gitlab.com:group/subgroup/repo.git"
	if strings.HasPrefix(s, "git@") {
		s = s[4:]
		if colonIdx := strings.Index(s, ":"); colonIdx != -1 && !strings.Contains(s[:colonIdx], "/") {
			s = s[:colonIdx] + "/" + s[colonIdx+1:]
		}
	}

	// 3. Strip scheme (e.g. "https://", "http://", "ssh://", "git://", or protocol-relative "//")
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	} else {
		s = strings.TrimPrefix(s, "//")
	}

	// 4. Strip user credentials if still present (e.g. "user:pass@gitlab.com/...")
	if atIdx := strings.Index(s, "@"); atIdx != -1 {
		firstSlash := strings.Index(s, "/")
		if firstSlash == -1 || atIdx < firstSlash {
			s = s[atIdx+1:]
		}
	}

	// 5. Strip port from host component if present (e.g. "gitlab.acme.corp:8443/group/repo")
	firstSlash := strings.Index(s, "/")
	if firstSlash != -1 {
		hostPart := s[:firstSlash]
		pathPart := s[firstSlash:]
		if colonIdx := strings.LastIndex(hostPart, ":"); colonIdx != -1 {
			portStr := hostPart[colonIdx+1:]
			if _, err := strconv.Atoi(portStr); err == nil {
				s = hostPart[:colonIdx] + pathPart
			}
		}
	} else {
		if colonIdx := strings.LastIndex(s, ":"); colonIdx != -1 {
			portStr := s[colonIdx+1:]
			if _, err := strconv.Atoi(portStr); err == nil {
				s = s[:colonIdx]
			}
		}
	}

	// 6. Strip trailing ".git" suffix
	s = strings.TrimSuffix(s, ".git")

	// 7. Clean path slashes
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}
	s = path.Clean("/" + s)
	s = strings.Trim(s, "/")
	if s == "." || s == "" {
		return ""
	}

	// 8. Lowercase
	return strings.ToLower(s)
}

// matchesNamespaceTree performs hierarchical path and wildcard matching between
// a normalized pattern and normalized candidate target.
func matchesNamespaceTree(p, t string) bool {
	if p == "" || t == "" {
		return false
	}

	// 1. Universal wildcards
	if p == "*" || p == "all" || p == "**" {
		return true
	}

	// 2. Direct exact match
	if p == t {
		return true
	}

	// 3. Trailing recursive wildcard (e.g. "devops/*" or "devops/**")
	if strings.HasSuffix(p, "/*") || strings.HasSuffix(p, "/**") {
		base := strings.TrimSuffix(p, "/*")
		base = strings.TrimSuffix(base, "/**")
		base = strings.TrimRight(base, "/")

		// Authorize root group itself (e.g. target "devops" matches "devops/*")
		if matchesNamespaceTree(base, t) {
			return true
		}

		// Authorize all descendants (target must start with base + "/")
		if strings.HasPrefix(t, base+"/") {
			return true
		}

		// If base contains wildcards (e.g. "acme-*/*" or "**/audit/*")
		if strings.ContainsAny(base, "*?[") {
			baseParts := splitPathSegments(base)
			tParts := splitPathSegments(t)
			if !strings.Contains(base, "**") {
				if len(tParts) > len(baseParts) {
					tPrefix := strings.Join(tParts[:len(baseParts)], "/")
					if matchesNamespaceTree(base, tPrefix) {
						return true
					}
				}
			} else {
				for i := 1; i < len(tParts); i++ {
					tPrefix := strings.Join(tParts[:i], "/")
					if matchesNamespaceTree(base, tPrefix) {
						return true
					}
				}
			}
		}
		return false
	}

	// 4. Non-wildcard hierarchical root (e.g. "devops" authorizes "devops/backend", "devops/backend/service")
	if !strings.ContainsAny(p, "*?[") {
		return strings.HasPrefix(t, p+"/")
	}

	// 5. Glob matching for patterns with wildcards (e.g. "team-*", "acme-*/backend")
	if matchFeaturePattern(p, t) {
		return true
	}

	// Check descendant matching when pattern has wildcards (e.g. "team-*" matching "team-alpha/backend")
	pParts := splitPathSegments(p)
	tParts := splitPathSegments(t)
	if !strings.Contains(p, "**") {
		if len(tParts) > len(pParts) {
			tPrefix := strings.Join(tParts[:len(pParts)], "/")
			if matchFeaturePattern(p, tPrefix) {
				return true
			}
		}
	} else {
		for i := 1; i < len(tParts); i++ {
			tPrefix := strings.Join(tParts[:i], "/")
			if matchFeaturePattern(p, tPrefix) {
				return true
			}
		}
	}

	return false
}

// matchesNamespacePattern evaluates whether a target namespace matches an allowed pattern.
// It normalizes both pattern and target using NormalizeNamespace, supports hierarchical tree
// matching (root and descendants), and handles host-qualified patterns or targets.
func matchesNamespacePattern(pattern, target string) bool {
	p := NormalizeNamespace(pattern)
	t := NormalizeNamespace(target)
	if p == "" || t == "" {
		return false
	}

	// 1. Universal wildcards
	if p == "*" || p == "all" || p == "**" {
		return true
	}

	// 2. Direct tree match against target
	if matchesNamespaceTree(p, t) {
		return true
	}

	// 3. Handle host-aware target vs pattern
	// Check if target has a slash separating first segment and path
	if tFirstSlash := strings.Index(t, "/"); tFirstSlash != -1 {
		tHost := t[:tFirstSlash]
		tPath := t[tFirstSlash+1:]

		// If pattern also has slashes:
		if pFirstSlash := strings.Index(p, "/"); pFirstSlash != -1 {
			pHost := p[:pFirstSlash]
			pPath := p[pFirstSlash+1:]

			// If pattern has a host component (contains dot or wildcard prefix):
			if strings.Contains(pHost, ".") || strings.HasPrefix(pHost, "*.") {
				if matchesHostPattern(pHost, tHost) && matchesNamespaceTree(pPath, tPath) {
					return true
				}
			} else {
				// Pattern has slashes but no host (e.g. "devops/backend/*")
				// If target has a host (contains dot or is localhost), match pattern against target's path
				if strings.Contains(tHost, ".") || tHost == "localhost" {
					if matchesNamespaceTree(p, tPath) {
						return true
					}
				}
			}
		} else {
			// Pattern has no slashes (e.g. "devops")
			// If target has a host (contains dot or is localhost) and pattern has no dot:
			if (strings.Contains(tHost, ".") || tHost == "localhost") && !strings.Contains(p, ".") {
				if matchesNamespaceTree(p, tPath) {
					return true
				}
			}
		}
	}

	return false
}

// matchesNamespaceScope evaluates whether target matches any namespace pattern in allowed.
// If allowed is empty, returns true (unrestricted).
// If target is empty, returns false.
func matchesNamespaceScope(allowed []string, target string) bool {
	if len(allowed) == 0 {
		return true
	}
	normTarget := NormalizeNamespace(target)
	if normTarget == "" {
		return false
	}

	for _, entry := range allowed {
		if matchesNamespacePattern(entry, normTarget) {
			return true
		}
	}
	return false
}

// IsVersionAllowed evaluates whether the given software version is authorized by the license.
// If neither MaxVersion nor AllowedVersions is specified, all versions are permitted (returns true).
// If version is empty, it returns false when version constraints are configured.
func (c *Claims) IsVersionAllowed(version string) bool {
	v := strings.TrimSpace(version)
	if c.MaxVersion == "" && len(c.AllowedVersions) == 0 {
		return true // unconstrained
	}
	if v == "" {
		return false
	}

	// 1. Check AllowedVersions if configured
	if len(c.AllowedVersions) > 0 {
		matched := false
		for _, pattern := range c.AllowedVersions {
			if matchVersionPattern(pattern, v) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 2. Check MaxVersion if configured
	if c.MaxVersion != "" {
		if !checkMaxVersion(c.MaxVersion, v) {
			return false
		}
	}

	return true
}

// IsMaintenanceActiveAt reports whether software updates/releases built at buildDate are entitled.
// If MaintenanceExpiresAt is zero, returns true (no cutoff configured).
func (c *Claims) IsMaintenanceActiveAt(buildDate time.Time) bool {
	if c.MaintenanceExpiresAt.IsZero() {
		return true
	}
	if buildDate.IsZero() {
		return false
	}
	return !buildDate.After(c.MaintenanceExpiresAt)
}

// HasMaintenanceExpired reports whether a build date exceeds the maintenance cutoff.
func (c *Claims) HasMaintenanceExpired(buildDate time.Time) bool {
	if c.MaintenanceExpiresAt.IsZero() {
		return false
	}
	if buildDate.IsZero() {
		return false
	}
	return buildDate.After(c.MaintenanceExpiresAt)
}

// matchVersionPattern checks if a target version matches a pattern.
func matchVersionPattern(pattern, version string) bool {
	return helpers.MatchVersionPattern(pattern, version)
}

// checkMaxVersion asserts that version does not exceed maxVersion.
func checkMaxVersion(maxVersion, version string) bool {
	return helpers.CheckMaxVersion(maxVersion, version)
}
