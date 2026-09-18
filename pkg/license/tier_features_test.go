package license

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestClaims_HasFeatureWithTiers(t *testing.T) {
	tierMatrix := TierFeatures{
		"community":  {"basic-ingest"},
		"starter":    {"basic-ingest", "email-alerts"},
		"pro":        {"basic-ingest", "email-alerts", "sso", "audit.*"},
		"enterprise": {"*"},
	}

	// 1. Pro plan user
	proClaims := &Claims{
		Plan: "pro",
	}

	if !proClaims.HasFeatureWithTiers("basic-ingest", tierMatrix) {
		t.Error("expected Pro to have basic-ingest")
	}
	if !proClaims.HasFeatureWithTiers("email-alerts", tierMatrix) {
		t.Error("expected Pro to have email-alerts")
	}
	if !proClaims.HasFeatureWithTiers("sso", tierMatrix) {
		t.Error("expected Pro to have sso")
	}
	if !proClaims.HasFeatureWithTiers("SSO", tierMatrix) {
		t.Error("expected Pro to have SSO (case-insensitive)")
	}
	if !proClaims.HasFeatureWithTiers("audit.view", tierMatrix) {
		t.Error("expected Pro to have audit.view via glob")
	}
	if !proClaims.HasFeatureWithTiers("audit.export", tierMatrix) {
		t.Error("expected Pro to have audit.export via glob")
	}
	if proClaims.HasFeatureWithTiers("dedicated-support", tierMatrix) {
		t.Error("expected Pro NOT to have dedicated-support")
	}

	// 2. Enterprise plan user (wildcard "*")
	entClaims := &Claims{
		Plan: "enterprise",
	}
	if !entClaims.HasFeatureWithTiers("anything-under-the-sun", tierMatrix) {
		t.Error("expected Enterprise to have all features via wildcard *")
	}

	// 3. Starter plan user with an a-la-carte add-on in Claims.Features
	starterClaims := &Claims{
		Plan:     "starter",
		Features: []string{"sso"}, // Add-on purchased separately!
	}
	if !starterClaims.HasFeatureWithTiers("basic-ingest", tierMatrix) {
		t.Error("expected Starter to have basic-ingest via tier")
	}
	if !starterClaims.HasFeatureWithTiers("sso", tierMatrix) {
		t.Error("expected Starter to have sso via explicit token add-on")
	}
	if starterClaims.HasFeatureWithTiers("audit.view", tierMatrix) {
		t.Error("expected Starter NOT to have audit.view")
	}

	// 4. Case-insensitivity in Plan name
	proUpperClaims := &Claims{
		Plan: "PRO",
	}
	if !proUpperClaims.HasFeatureWithTiers("sso", tierMatrix) {
		t.Error("expected PRO plan to match pro tier case-insensitively")
	}

	// 5. Nil claims safety
	var nilClaims *Claims
	if nilClaims.HasFeatureWithTiers("sso", tierMatrix) {
		t.Error("expected nil claims to return false")
	}
}

func TestClaims_WithTierFeatures_And_HasFeature(t *testing.T) {
	tierMatrix := TierFeatures{
		"starter": {"basic-runners"},
		"pro":     {"basic-runners", "sso", "metrics"},
	}

	claims := (&Claims{
		Plan:     "starter",
		Features: []string{"custom-reporting"},
	}).WithTierFeatures(tierMatrix)

	if claims.TierFeatures() == nil {
		t.Fatal("expected TierFeatures to be attached")
	}

	// Should have starter feature
	if !claims.HasFeature("basic-runners") {
		t.Error("expected HasFeature to evaluate tier features")
	}
	// Should have token add-on feature
	if !claims.HasFeature("custom-reporting") {
		t.Error("expected HasFeature to evaluate token features")
	}
	// Should NOT have pro-only feature
	if claims.HasFeature("sso") {
		t.Error("expected starter plan without sso add-on to return false")
	}

	// Test SetTierFeatures update
	claims.SetTierFeatures(TierFeatures{
		"starter": {"basic-runners", "sso"}, // Feature moved to starter in newer version!
	})
	if !claims.HasFeature("sso") {
		t.Error("expected updated tier matrix to immediately entitle sso without token re-issuance")
	}
}

func TestClaims_EffectiveFeatures(t *testing.T) {
	tierMatrix := TierFeatures{
		"pro": {"basic-runners", "sso", "metrics"},
	}

	claims := (&Claims{
		Plan:     "pro",
		Features: []string{"custom-reporting", "sso"}, // "sso" duplicated in token
	}).WithTierFeatures(tierMatrix)

	effective := claims.EffectiveFeatures()

	expected := []string{"basic-runners", "sso", "metrics", "custom-reporting"}
	if len(effective) != len(expected) {
		t.Fatalf("expected %d effective features, got %d: %v", len(expected), len(effective), effective)
	}

	for i, exp := range expected {
		if effective[i] != exp {
			t.Errorf("expected feature[%d] = %q, got %q", i, exp, effective[i])
		}
	}
}

func TestClaims_JSONExclusion(t *testing.T) {
	tierMatrix := TierFeatures{
		"pro": {"sso"},
	}
	claims := (&Claims{
		ID:       "test-id",
		Product:  "test-prod",
		Plan:     "pro",
		Customer: Customer{Name: "Acme"},
		IssuedAt: time.Now().UTC(),
	}).WithTierFeatures(tierMatrix)

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	// Ensure tierFeatures is NOT serialized to JSON wire format
	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if _, exists := unmarshaled["tierFeatures"]; exists {
		t.Error("tierFeatures should not be serialized into JSON")
	}
	if _, exists := unmarshaled["tier_features"]; exists {
		t.Error("tier_features should not be serialized into JSON")
	}
}

func TestValidator_WithTierFeatures(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Token only has Plan: "pro", no features listed!
	claims := Claims{
		Customer: Customer{Name: "Acme Corp"},
		Product:  "gitlab-fleet-governor",
		Plan:     "pro",
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	tierMatrix := TierFeatures{
		"pro":        {"runner-management", "sso"},
		"enterprise": {"*"},
	}

	validator, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithTierFeatures(tierMatrix),
	)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := validator.Verify(token)
	if err != nil {
		t.Fatalf("validator.Verify failed: %v", err)
	}

	if !verified.HasFeature("runner-management") {
		t.Error("expected verified claims to have runner-management via validator tier matrix")
	}
	if !verified.HasFeature("sso") {
		t.Error("expected verified claims to have sso via validator tier matrix")
	}
	if verified.HasFeature("dedicated-cloud") {
		t.Error("expected verified claims NOT to have dedicated-cloud")
	}

	// VerifyWithResult test
	result, err := validator.VerifyWithResult(token)
	if err != nil {
		t.Fatalf("validator.VerifyWithResult failed: %v", err)
	}
	if !result.Claims.HasFeature("sso") {
		t.Error("expected result.Claims to have sso via validator tier matrix")
	}
}

func TestManager_WithTierFeatures(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	tierMatrix := TierFeatures{
		"community":  {"basic-ingest"},
		"starter":    {"basic-ingest", "alerts"},
		"pro":        {"basic-ingest", "alerts", "sso"},
		"enterprise": {"*"},
	}

	validator, err := NewValidator(pub,
		WithProduct("otel-aws-log-processor"),
		WithTierFeatures(tierMatrix),
	)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Active Pro license token
	claims := Claims{
		Customer: Customer{Name: "Acme Corp"},
		Product:  "otel-aws-log-processor",
		Plan:     "pro",
		Features: []string{"audit-add-on"},
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: token,
		Policy:        PolicyStrict,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)

	// HasFeature checks
	if !mgr.HasFeature("basic-ingest") {
		t.Error("expected manager to have basic-ingest via pro tier")
	}
	if !mgr.HasFeature("sso") {
		t.Error("expected manager to have sso via pro tier")
	}
	if !mgr.HasFeature("audit-add-on") {
		t.Error("expected manager to have audit-add-on via token add-on")
	}
	if mgr.HasFeature("custom-encryption") {
		t.Error("expected manager NOT to have custom-encryption")
	}

	// AssertFeature checks
	if err := mgr.AssertFeature("sso"); err != nil {
		t.Errorf("expected AssertFeature(sso) == nil, got: %v", err)
	}
	if err := mgr.AssertFeature("custom-encryption"); err == nil || !errors.Is(err, ErrFeatureNotEntitled) {
		t.Errorf("expected ErrFeatureNotEntitled for custom-encryption, got: %v", err)
	}

	// 2. Degraded mode fallback claims with community tier features
	degradedMgr, err := NewManager(ManagerConfig{
		Validator:     validator,
		LicenseString: "invalid-token",
		Policy:        PolicyDegraded,
		FallbackClaims: &Claims{
			Product:  "otel-aws-log-processor",
			Plan:     "community",
			Customer: Customer{Name: "Community Fallback"},
		},
	})
	if err != nil {
		t.Fatalf("NewManager degraded failed: %v", err)
	}
	degradedMgr.Start(ctx)

	if !degradedMgr.HasFeature("basic-ingest") {
		t.Error("expected degraded manager to have basic-ingest via community tier")
	}
	if degradedMgr.HasFeature("sso") {
		t.Error("expected degraded manager NOT to have sso")
	}
}
