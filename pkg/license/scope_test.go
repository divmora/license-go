package license

import (
	"errors"
	"testing"
)

func TestScope_ClaimsHelpers(t *testing.T) {
	claims := sampleClaims()
	claims.Scope = &Scope{
		Environments: []string{"production", "staging-*"},
		Accounts:     []string{"123456789012", "987654321098"},
		Regions:      []string{"us-east-1", "eu-west-*"},
		Clusters:     []string{"prod-k8s-*"},
		Namespaces:   []string{"gitlab.com/acme-corp/*"},
		Hosts:        []string{"*.acme.corp", "runner-*.internal"},
		Custom: map[string][]string{
			"tier": {"platinum", "gold"},
		},
	}

	// 1. Environments
	if !claims.IsEnvironmentAllowed("production") {
		t.Error("expected production to be allowed")
	}
	if !claims.IsEnvironmentAllowed("staging-eu") {
		t.Error("expected staging-eu to be allowed by staging-*")
	}
	if claims.IsEnvironmentAllowed("development") {
		t.Error("expected development to be disallowed")
	}

	// 2. Accounts
	if !claims.IsAccountAllowed("123456789012") {
		t.Error("expected account 123456789012 to be allowed")
	}
	if claims.IsAccountAllowed("111111111111") {
		t.Error("expected account 111111111111 to be disallowed")
	}

	// 3. Regions
	if !claims.IsRegionAllowed("us-east-1") {
		t.Error("expected us-east-1 to be allowed")
	}
	if !claims.IsRegionAllowed("eu-west-1") {
		t.Error("expected eu-west-1 to be allowed by eu-west-*")
	}
	if claims.IsRegionAllowed("ap-south-1") {
		t.Error("expected ap-south-1 to be disallowed")
	}

	// 4. Clusters
	if !claims.IsClusterAllowed("prod-k8s-01") {
		t.Error("expected prod-k8s-01 to be allowed by prod-k8s-*")
	}
	if claims.IsClusterAllowed("dev-k8s-01") {
		t.Error("expected dev-k8s-01 to be disallowed")
	}

	// 5. Namespaces
	if !claims.IsNamespaceAllowed("gitlab.com/acme-corp/project-a") {
		t.Error("expected gitlab.com/acme-corp/project-a to be allowed")
	}
	if claims.IsNamespaceAllowed("gitlab.com/evil-corp/project-a") {
		t.Error("expected gitlab.com/evil-corp/project-a to be disallowed")
	}

	// 6. Hosts
	if !claims.IsHostAllowed("runner-01.acme.corp") {
		t.Error("expected runner-01.acme.corp to be allowed by *.acme.corp")
	}
	if !claims.IsHostAllowed("runner-aws-01.internal") {
		t.Error("expected runner-aws-01.internal to be allowed by runner-*.internal")
	}
	if claims.IsHostAllowed("evil.com") {
		t.Error("expected evil.com to be disallowed")
	}

	// 7. Custom dimensions
	if !claims.IsInScope("tier", "platinum") {
		t.Error("expected custom tier platinum to be allowed")
	}
	if claims.IsInScope("tier", "bronze") {
		t.Error("expected custom tier bronze to be disallowed")
	}

	// 8. AssertScope
	if err := claims.AssertScope("environments", "production"); err != nil {
		t.Errorf("AssertScope(environments, production) failed: %v", err)
	}
	if err := claims.AssertScope("environments", "dev"); err == nil || !errors.Is(err, ErrScopeMismatch) {
		t.Errorf("expected ErrScopeMismatch for dev, got %v", err)
	}
}

func TestScope_UnscopedPermitsAll(t *testing.T) {
	unscoped := sampleClaims()
	unscoped.Scope = nil
	unscoped.Environment = ""

	if !unscoped.IsEnvironmentAllowed("any-env") {
		t.Error("expected unscoped to permit any environment")
	}
	if !unscoped.IsAccountAllowed("999999999999") {
		t.Error("expected unscoped to permit any account")
	}
	if !unscoped.IsRegionAllowed("ap-northeast-1") {
		t.Error("expected unscoped to permit any region")
	}
	if !unscoped.IsClusterAllowed("cluster-xyz") {
		t.Error("expected unscoped to permit any cluster")
	}
	if !unscoped.IsNamespaceAllowed("any/namespace/path") {
		t.Error("expected unscoped to permit any namespace")
	}
	if !unscoped.IsHostAllowed("anything.example.com") {
		t.Error("expected unscoped to permit any host")
	}
}

func TestScope_ValidatorEnforcement(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, _ := NewSigner(priv)

	claims := sampleClaims()
	claims.Scope = &Scope{
		Environments: []string{"production"},
		Accounts:     []string{"123456789012"},
		Regions:      []string{"us-east-1"},
		Clusters:     []string{"prod-cluster"},
		Namespaces:   []string{"gitlab.com/acme/*"},
		Hosts:        []string{"*.acme.corp"},
	}

	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	// 1. Validator matching all scope dimensions -> SUCCESS
	vMatching, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentEnvironment("production"),
		WithCurrentAccount("123456789012"),
		WithCurrentRegion("us-east-1"),
		WithCurrentCluster("prod-cluster"),
		WithCurrentNamespace("gitlab.com/acme/core"),
		WithCurrentHost("srv-01.acme.corp"),
	)
	if _, err := vMatching.Verify(token); err != nil {
		t.Fatalf("expected verification to succeed with matching scopes: %v", err)
	}

	// 2. Mismatch on Environment -> FAIL with ErrScopeMismatch
	vEnvMismatch, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentEnvironment("staging"),
		WithCurrentAccount("123456789012"),
		WithCurrentRegion("us-east-1"),
		WithCurrentCluster("prod-cluster"),
		WithCurrentNamespace("gitlab.com/acme/core"),
		WithCurrentHost("srv-01.acme.corp"),
	)
	_, err = vEnvMismatch.Verify(token)
	if err == nil || !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("expected ErrScopeMismatch on environment, got %v", err)
	}

	// 3. Mismatch on Host -> FAIL with ErrScopeMismatch
	vHostMismatch, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentEnvironment("production"),
		WithCurrentAccount("123456789012"),
		WithCurrentRegion("us-east-1"),
		WithCurrentCluster("prod-cluster"),
		WithCurrentNamespace("gitlab.com/acme/core"),
		WithCurrentHost("srv-01.unauthorized.com"),
	)
	_, err = vHostMismatch.Verify(token)
	if err == nil || !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("expected ErrScopeMismatch on host, got %v", err)
	}

	// 4. Mismatch on Account -> FAIL with ErrScopeMismatch
	vAccountMismatch, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentEnvironment("production"),
		WithCurrentAccount("999999999999"),
		WithCurrentRegion("us-east-1"),
		WithCurrentCluster("prod-cluster"),
		WithCurrentNamespace("gitlab.com/acme/core"),
		WithCurrentHost("srv-01.acme.corp"),
	)
	_, err = vAccountMismatch.Verify(token)
	if err == nil || !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("expected ErrScopeMismatch on account, got %v", err)
	}
}
