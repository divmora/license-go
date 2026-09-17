package license

import (
	"errors"
	"testing"
	"time"
)

func TestClaims_IsTrial(t *testing.T) {
	cTrial := Claims{Plan: "trial"}
	if !cTrial.IsTrial() {
		t.Error("expected IsTrial to return true for 'trial'")
	}
	cTrialCap := Claims{Plan: "TRIAL"}
	if !cTrialCap.IsTrial() {
		t.Error("expected IsTrial to return true for 'TRIAL'")
	}
	cEnt := Claims{Plan: "enterprise"}
	if cEnt.IsTrial() {
		t.Error("expected IsTrial to return false for 'enterprise'")
	}
}

func TestScope_NilAndEmptyScopeMethods(t *testing.T) {
	var nilScope *Scope
	if !nilScope.IsEnvironmentAllowed("prod") {
		t.Error("expected nilScope.IsEnvironmentAllowed to return true")
	}
	if !nilScope.IsAccountAllowed("123456") {
		t.Error("expected nilScope.IsAccountAllowed to return true")
	}
	if !nilScope.IsRegionAllowed("us-east-1") {
		t.Error("expected nilScope.IsRegionAllowed to return true")
	}
	if !nilScope.IsClusterAllowed("cluster-1") {
		t.Error("expected nilScope.IsClusterAllowed to return true")
	}
	if !nilScope.IsNamespaceAllowed("gitlab.com/acme/project") {
		t.Error("expected nilScope.IsNamespaceAllowed to return true")
	}
	if !nilScope.IsHostAllowed("app.acme.corp") {
		t.Error("expected nilScope.IsHostAllowed to return true")
	}

	emptyScope := &Scope{}
	if !emptyScope.IsEnvironmentAllowed("prod") {
		t.Error("expected emptyScope.IsEnvironmentAllowed to return true")
	}
	if !emptyScope.IsAccountAllowed("123456") {
		t.Error("expected emptyScope.IsAccountAllowed to return true")
	}
	if !emptyScope.IsRegionAllowed("us-east-1") {
		t.Error("expected emptyScope.IsRegionAllowed to return true")
	}
	if !emptyScope.IsClusterAllowed("cluster-1") {
		t.Error("expected emptyScope.IsClusterAllowed to return true")
	}
	if !emptyScope.IsNamespaceAllowed("gitlab.com/acme/project") {
		t.Error("expected emptyScope.IsNamespaceAllowed to return true")
	}
	if !emptyScope.IsHostAllowed("app.acme.corp") {
		t.Error("expected emptyScope.IsHostAllowed to return true")
	}
}

func TestClaims_GetMetadata(t *testing.T) {
	claims := Claims{
		Metadata: map[string]string{
			"env":    "production",
			"tier":   "platinum",
			"Region": "us-east-1",
		},
	}

	val, ok := claims.GetMetadata("env")
	if !ok || val != "production" {
		t.Errorf("expected 'production', got %q, ok=%v", val, ok)
	}

	val, ok = claims.GetMetadata("region")
	if !ok || val != "us-east-1" {
		t.Errorf("expected case-insensitive match for region, got %q, ok=%v", val, ok)
	}

	_, ok = claims.GetMetadata("missing")
	if ok {
		t.Error("expected missing key to return ok=false")
	}

	var emptyClaims Claims
	_, ok = emptyClaims.GetMetadata("any")
	if ok {
		t.Error("expected nil metadata to return ok=false")
	}
}

func TestClaims_AssertScope_Comprehensive(t *testing.T) {
	claims := Claims{
		Scope: &Scope{
			Environments: []string{"production", "staging"},
			Accounts:     []string{"123456789012"},
			Regions:      []string{"us-east-1", "eu-west-1"},
			Clusters:     []string{"k8s-prod-*"},
			Namespaces:   []string{"gitlab.com/acme/*"},
			Hosts:        []string{"*.acme.corp"},
			Custom: map[string][]string{
				"datacenter": {"dc-east", "dc-west"},
			},
		},
	}

	// Success cases
	if err := claims.AssertScope("environments", "production"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := claims.AssertScope("account", "123456789012"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := claims.AssertScope("region", "us-east-1"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := claims.AssertScope("cluster", "k8s-prod-alpha"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := claims.AssertScope("namespace", "gitlab.com/acme/project"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := claims.AssertScope("host", "api.acme.corp"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := claims.AssertScope("datacenter", "dc-east"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Failure cases
	tests := []struct {
		dimension string
		target    string
	}{
		{"environments", "development"},
		{"accounts", "999999999999"},
		{"regions", "ap-southeast-1"},
		{"clusters", "k8s-dev-01"},
		{"namespaces", "gitlab.com/other/*"},
		{"hosts", "api.evil.com"},
		{"datacenter", "dc-central"},
	}

	for _, tc := range tests {
		err := claims.AssertScope(tc.dimension, tc.target)
		if err == nil || !errors.Is(err, ErrScopeMismatch) {
			t.Errorf("AssertScope(%q, %q) expected ErrScopeMismatch, got %v", tc.dimension, tc.target, err)
		}
	}

	// Empty claims without scope passes all AssertScope
	emptyClaims := Claims{}
	if err := emptyClaims.AssertScope("environments", "prod"); err != nil {
		t.Errorf("expected empty claims to permit all, got: %v", err)
	}
}

func TestClaims_IsMaintenanceActiveAt(t *testing.T) {
	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	claimsWithCutoff := Claims{
		MaintenanceExpiresAt: cutoff,
	}

	// 1. Zero build date returns false
	if claimsWithCutoff.IsMaintenanceActiveAt(time.Time{}) {
		t.Error("expected zero build date to return false")
	}
	if claimsWithCutoff.HasMaintenanceExpired(time.Time{}) {
		t.Error("expected zero build date to report not expired")
	}

	// 2. Build date before cutoff returns true
	if !claimsWithCutoff.IsMaintenanceActiveAt(cutoff.Add(-24 * time.Hour)) {
		t.Error("expected date before cutoff to be active")
	}
	if claimsWithCutoff.HasMaintenanceExpired(cutoff.Add(-24 * time.Hour)) {
		t.Error("expected date before cutoff to not be expired")
	}

	// 3. Build date after cutoff returns false
	if claimsWithCutoff.IsMaintenanceActiveAt(cutoff.Add(24 * time.Hour)) {
		t.Error("expected date after cutoff to not be active")
	}
	if !claimsWithCutoff.HasMaintenanceExpired(cutoff.Add(24 * time.Hour)) {
		t.Error("expected date after cutoff to be expired")
	}

	// 4. Zero MaintenanceExpiresAt returns true (no cutoff)
	claimsNoCutoff := Claims{}
	if !claimsNoCutoff.IsMaintenanceActiveAt(cutoff) {
		t.Error("expected unconfigured cutoff to return true")
	}
	if claimsNoCutoff.HasMaintenanceExpired(cutoff) {
		t.Error("expected unconfigured cutoff to report not expired")
	}
}

func TestClaims_GraceDaysRemainingAt(t *testing.T) {
	now := time.Now().UTC()
	c := Claims{
		ExpiresAt:       now.Add(-2 * 24 * time.Hour), // expired 2 days ago
		GracePeriodDays: 7,                            // 5 days remaining
	}

	// Active in grace period
	if !c.IsInGracePeriodAt(now) {
		t.Error("expected to be in grace period")
	}
	days := c.GraceDaysRemainingAt(now)
	if days < 4 || days > 5 {
		t.Errorf("expected ~5 days remaining, got %d", days)
	}

	// GraceDaysRemaining convenience wrapper
	_ = c.GraceDaysRemaining()

	// With skew parameter
	daysWithSkew := c.GraceDaysRemainingAt(now, 10*time.Minute)
	if daysWithSkew < 4 || daysWithSkew > 5 {
		t.Errorf("expected ~5 days remaining with skew, got %d", daysWithSkew)
	}

	// Expired completely (past grace period)
	cExpired := Claims{
		ExpiresAt:       now.Add(-10 * 24 * time.Hour),
		GracePeriodDays: 7,
	}
	if cExpired.GraceDaysRemainingAt(now) != 0 {
		t.Errorf("expected 0 grace days remaining for completely expired license")
	}

	// Not yet expired
	cActive := Claims{
		ExpiresAt:       now.Add(10 * 24 * time.Hour),
		GracePeriodDays: 7,
	}
	if cActive.GraceDaysRemainingAt(now) != 0 {
		t.Errorf("expected 0 grace days remaining for active unexpired license")
	}
}

func TestClaims_HasScopeDimension_Exhaustive(t *testing.T) {
	cNil := Claims{}
	if cNil.HasScopeDimension("environments") {
		t.Error("nil scope should have no dimensions")
	}
	if cNil.HasScopeDimension("custom_dim") {
		t.Error("nil scope should have no custom dimensions")
	}

	// Environment directly on Claims
	cDirectEnv := Claims{Environment: "production"}
	if !cDirectEnv.HasScopeDimension("env") {
		t.Error("expected true for env with Environment set")
	}
	if !cDirectEnv.HasScopeDimension("environments") {
		t.Error("expected true for environments with Environment set")
	}

	// Populated scope
	cPopulated := Claims{
		Scope: &Scope{
			Environments: []string{"prod"},
			Accounts:     []string{"123"},
			Regions:      []string{"us-east-1"},
			Clusters:     []string{"c1"},
			Namespaces:   []string{"ns1"},
			Hosts:        []string{"example.com"},
			Custom: map[string][]string{
				"tier": {"gold"},
				"rack": {},
			},
		},
	}

	dims := []string{
		"environments", "environment", "env",
		"accounts", "account",
		"regions", "region",
		"clusters", "cluster",
		"namespaces", "namespace", "groups", "group",
		"hosts", "host", "domain", "domains",
		"tier",
	}
	for _, dim := range dims {
		if !cPopulated.HasScopeDimension(dim) {
			t.Errorf("expected HasScopeDimension(%q) to return true", dim)
		}
	}

	// Empty custom slice
	if cPopulated.HasScopeDimension("rack") {
		t.Error("expected false for custom dimension with empty slice")
	}

	// Non-existent custom dimension
	if cPopulated.HasScopeDimension("non_existent") {
		t.Error("expected false for non-existent dimension")
	}
}

func TestScope_WhitespaceAndEmptyMatches(t *testing.T) {
	s := &Scope{
		Hosts:      []string{"app.divmora.io"},
		Namespaces: []string{"divmora/core"},
	}

	if s.IsHostAllowed("") {
		t.Error("expected empty host target to be rejected when hosts are constrained")
	}
	if s.IsHostAllowed("   ") {
		t.Error("expected whitespace host target to be rejected when hosts are constrained")
	}

	if s.IsNamespaceAllowed("") {
		t.Error("expected empty namespace target to be rejected when namespaces are constrained")
	}
	if s.IsNamespaceAllowed("   ") {
		t.Error("expected whitespace namespace target to be rejected when namespaces are constrained")
	}
}

func TestClaims_GetLimit_Exhaustive(t *testing.T) {
	var cNil Claims
	if _, ok := cNil.GetLimit("max_nodes"); ok {
		t.Error("expected ok=false for nil limits")
	}

	c := Claims{
		Limits: map[string]int64{
			"max_nodes":   50,
			"Max_Runners": 200,
			"unlimited_q": -1,
		},
	}

	// Exact match
	val, ok := c.GetLimit("max_nodes")
	if !ok || val != 50 {
		t.Errorf("expected 50, true; got %d, %v", val, ok)
	}

	// Case-insensitive match
	val, ok = c.GetLimit("MAX_NODES")
	if !ok || val != 50 {
		t.Errorf("expected 50, true for MAX_NODES; got %d, %v", val, ok)
	}

	val, ok = c.GetLimit("max_runners")
	if !ok || val != 200 {
		t.Errorf("expected 200, true for max_runners; got %d, %v", val, ok)
	}

	// Non-existent key
	_, ok = c.GetLimit("missing_key")
	if ok {
		t.Error("expected ok=false for missing key")
	}

	// CheckLimit within limit
	if err := c.CheckLimit("max_nodes", 50); err != nil {
		t.Errorf("expected no error at limit, got: %v", err)
	}

	// CheckLimit exceeds limit
	if err := c.CheckLimit("max_nodes", 51); err == nil {
		t.Error("expected LimitExceededError when usage exceeds limit")
	}

	// CheckLimit unlimited (-1)
	if err := c.CheckLimit("unlimited_q", 100000); err != nil {
		t.Errorf("expected no error for unlimited limit (-1), got: %v", err)
	}

	// CheckLimit missing key returns nil
	if err := c.CheckLimit("non_existent", 9999); err != nil {
		t.Errorf("expected no error for undefined limit, got: %v", err)
	}
}

func TestClaims_HierarchicalFeatureMatching(t *testing.T) {
	c := Claims{
		Features: []string{
			"audit/export/**",
			"reports/*/pdf",
			"sso",
		},
	}

	if !c.HasFeature("audit/export/csv") {
		t.Error("expected match for audit/export/csv against audit/export/**")
	}
	if !c.HasFeature("audit/export/daily/archive") {
		t.Error("expected match for deep path against audit/export/**")
	}
	if !c.HasFeature("reports/monthly/pdf") {
		t.Error("expected match for reports/monthly/pdf against reports/*/pdf")
	}
	if c.HasFeature("reports/monthly/csv") {
		t.Error("expected false for reports/monthly/csv")
	}
	if !c.HasFeature("sso") {
		t.Error("expected match for sso")
	}
	if c.HasFeature("non_existent") {
		t.Error("expected false for non_existent")
	}
}

func TestScope_WildcardMatchingAndEmptyRejections(t *testing.T) {
	s := &Scope{
		Environments: []string{"prod-*", "staging"},
		Accounts:     []string{"*"},
		Regions:      []string{"us-west-?", "all"},
		Clusters:     []string{"cluster-[a-z]"},
	}

	// 1. Wildcard matches
	if !s.IsEnvironmentAllowed("prod-us") {
		t.Error("expected match for prod-us against prod-*")
	}
	if s.IsEnvironmentAllowed("dev-1") {
		t.Error("expected false for dev-1")
	}

	// 2. Account "*" matches all
	if !s.IsAccountAllowed("123456789012") {
		t.Error("expected account wildcard '*' to match any account")
	}

	// 3. Region "?" and "all" matches
	if !s.IsRegionAllowed("us-west-1") {
		t.Error("expected us-west-1 to match us-west-?")
	}
	if !s.IsRegionAllowed("eu-central-1") {
		t.Error("expected eu-central-1 to match region 'all'")
	}

	// 4. Cluster character class "[a-z]"
	if !s.IsClusterAllowed("cluster-a") {
		t.Error("expected cluster-a to match cluster-[a-z]")
	}
	if s.IsClusterAllowed("cluster-1") {
		t.Error("expected false for cluster-1 against cluster-[a-z]")
	}

	// 5. Empty target strings rejected when constraints exist
	if s.IsEnvironmentAllowed("") || s.IsEnvironmentAllowed("   ") {
		t.Error("expected empty/whitespace environment to be rejected")
	}
	if s.IsAccountAllowed("") || s.IsAccountAllowed("   ") {
		t.Error("expected empty/whitespace account to be rejected")
	}
	if s.IsRegionAllowed("") || s.IsRegionAllowed("   ") {
		t.Error("expected empty/whitespace region to be rejected")
	}
	if s.IsClusterAllowed("") || s.IsClusterAllowed("   ") {
		t.Error("expected empty/whitespace cluster to be rejected")
	}
}
