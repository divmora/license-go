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

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "whitespace only", input: "   ", expected: ""},
		{name: "simple domain", input: "acme.corp", expected: "acme.corp"},
		{name: "uppercase domain", input: "GITLAB.ACME.CORP", expected: "gitlab.acme.corp"},
		{name: "trailing dot FQDN", input: "gitlab.acme.corp.", expected: "gitlab.acme.corp"},
		{name: "http scheme", input: "http://gitlab.acme.corp", expected: "gitlab.acme.corp"},
		{name: "https scheme", input: "https://gitlab.acme.corp", expected: "gitlab.acme.corp"},
		{name: "custom scheme", input: "grpc://my-service.internal", expected: "my-service.internal"},
		{name: "protocol relative", input: "//gitlab.acme.corp", expected: "gitlab.acme.corp"},
		{name: "port stripped", input: "gitlab.acme.corp:8080", expected: "gitlab.acme.corp"},
		{name: "https with port", input: "https://gitlab.acme.corp:8443", expected: "gitlab.acme.corp"},
		{name: "trailing slash stripped", input: "https://gitlab.acme.corp/", expected: "gitlab.acme.corp"},
		{name: "path stripped", input: "https://gitlab.acme.corp/api/v4/projects", expected: "gitlab.acme.corp"},
		{name: "query and fragment stripped", input: "gitlab.acme.corp:8080/dashboard?tab=1#status", expected: "gitlab.acme.corp"},
		{name: "userinfo stripped", input: "https://admin:secret@gitlab.acme.corp:443/api", expected: "gitlab.acme.corp"},
		{name: "localhost with port", input: "localhost:3000", expected: "localhost"},
		{name: "ipv4 with port", input: "http://192.168.1.100:9090/metrics", expected: "192.168.1.100"},
		{name: "ipv4 without port", input: "10.0.0.1", expected: "10.0.0.1"},
		{name: "ipv6 bracketed with port", input: "http://[2001:db8::1]:8080/path", expected: "2001:db8::1"},
		{name: "ipv6 bracketed without port", input: "[::1]", expected: "::1"},
		{name: "ipv6 literal unbracketed", input: "2001:db8::1", expected: "2001:db8::1"},
		{name: "wildcard domain", input: "*.acme.corp", expected: "*.acme.corp"},
		{name: "wildcard domain with scheme and port", input: "https://*.acme.corp:443/", expected: "*.acme.corp"},
		{name: "universal wildcard", input: "*", expected: "*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NormalizeHost(tt.input)
			if actual != tt.expected {
				t.Errorf("NormalizeHost(%q) = %q, want %q", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestScope_ApexDomainMatching(t *testing.T) {
	scope := &Scope{
		Hosts: []string{"*.acme.corp"},
	}

	// 1. Apex domain must be authorized
	if !scope.IsHostAllowed("acme.corp") {
		t.Error("expected apex domain 'acme.corp' to be authorized by '*.acme.corp'")
	}
	if !scope.IsHostAllowed("https://acme.corp") {
		t.Error("expected URL 'https://acme.corp' to be authorized by '*.acme.corp'")
	}
	if !scope.IsHostAllowed("https://acme.corp:443/dashboard") {
		t.Error("expected URL with port and path 'https://acme.corp:443/dashboard' to be authorized by '*.acme.corp'")
	}

	// 2. Direct subdomains must be authorized
	if !scope.IsHostAllowed("gitlab.acme.corp") {
		t.Error("expected 'gitlab.acme.corp' to be authorized by '*.acme.corp'")
	}
	if !scope.IsHostAllowed("https://gitlab.acme.corp:8443/api/v4") {
		t.Error("expected URL 'https://gitlab.acme.corp:8443/api/v4' to be authorized by '*.acme.corp'")
	}

	// 3. Multi-level subdomains must be authorized
	if !scope.IsHostAllowed("runners.us-east.gitlab.acme.corp") {
		t.Error("expected multi-level subdomain 'runners.us-east.gitlab.acme.corp' to be authorized by '*.acme.corp'")
	}

	// 4. Suffix collisions and unrelated domains must be disallowed
	disallowed := []string{
		"notacme.corp",
		"fake-acme.corp",
		"http://evil-acme.corp",
		"acme.com",
		"other.org",
		"corp",
	}
	for _, target := range disallowed {
		if scope.IsHostAllowed(target) {
			t.Errorf("expected target %q to be disallowed by '*.acme.corp'", target)
		}
	}
}

func TestScope_LeadingDotDomainMatching(t *testing.T) {
	scope := &Scope{
		Hosts: []string{".acme.corp"},
	}

	if !scope.IsHostAllowed("acme.corp") {
		t.Error("expected apex 'acme.corp' to be authorized by '.acme.corp'")
	}
	if !scope.IsHostAllowed("gitlab.acme.corp") {
		t.Error("expected subdomain 'gitlab.acme.corp' to be authorized by '.acme.corp'")
	}
	if scope.IsHostAllowed("evil.com") {
		t.Error("expected 'evil.com' to be disallowed by '.acme.corp'")
	}
}

func TestValidator_HostNormalizationAndApexMatching(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	claims := Claims{
		Customer: Customer{Name: "Acme Corp"},
		Product:  "gitlab-fleet-governor",
		Scope: &Scope{
			Hosts: []string{"*.acme.corp", "runner-*.internal"},
		},
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Target is full URL with apex domain -> SUCCESS
	vApex, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentHost("https://acme.corp:443/runners"),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	if _, err := vApex.Verify(token); err != nil {
		t.Errorf("expected apex URL to verify successfully, got: %v", err)
	}

	// 2. Target is full URL with subdomain and custom port -> SUCCESS
	vSub, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentHost("https://gitlab.acme.corp:8443/api/v4"),
	)
	if _, err := vSub.Verify(token); err != nil {
		t.Errorf("expected subdomain URL to verify successfully, got: %v", err)
	}

	// 3. Target is runner with internal port -> SUCCESS
	vInternal, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentHost("http://runner-01.internal:9090/"),
	)
	if _, err := vInternal.Verify(token); err != nil {
		t.Errorf("expected internal host to verify successfully, got: %v", err)
	}

	// 4. Target is unauthorized host URL -> FAIL with ErrScopeMismatch
	vDisallowed, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentHost("https://evil.corp:443/"),
	)
	_, err = vDisallowed.Verify(token)
	if err == nil || !errors.Is(err, ErrScopeMismatch) {
		t.Errorf("expected ErrScopeMismatch for unauthorized host, got: %v", err)
	}
}
