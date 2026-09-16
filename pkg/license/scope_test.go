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

func TestNormalizeNamespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "whitespace only", input: "   ", expected: ""},
		{name: "slash only", input: "/", expected: ""},
		{name: "multiple slashes only", input: "///", expected: ""},
		{name: "single group", input: "devops", expected: "devops"},
		{name: "uppercase group", input: "DEVOPS", expected: "devops"},
		{name: "leading and trailing slashes", input: "/devops/backend/", expected: "devops/backend"},
		{name: "redundant internal slashes", input: "devops///backend////service", expected: "devops/backend/service"},
		{name: "dot segments resolved", input: "devops/./backend", expected: "devops/backend"},
		{name: "parent dot segments resolved", input: "devops/sub/../backend", expected: "devops/backend"},
		{name: "http url", input: "http://gitlab.com/devops/backend", expected: "gitlab.com/devops/backend"},
		{name: "https url", input: "https://gitlab.com/devops/backend", expected: "gitlab.com/devops/backend"},
		{name: "git scheme", input: "git://gitlab.com/devops/backend", expected: "gitlab.com/devops/backend"},
		{name: "ssh scheme", input: "ssh://git@gitlab.com/devops/backend", expected: "gitlab.com/devops/backend"},
		{name: "protocol relative", input: "//gitlab.com/devops/backend", expected: "gitlab.com/devops/backend"},
		{name: "scp style git url", input: "git@gitlab.com:devops/backend.git", expected: "gitlab.com/devops/backend"},
		{name: "trailing git stripped", input: "https://gitlab.com/devops/backend.git", expected: "gitlab.com/devops/backend"},
		{name: "user credentials stripped", input: "https://user:token@gitlab.com/devops/backend", expected: "gitlab.com/devops/backend"},
		{name: "port stripped from host", input: "https://gitlab.acme.corp:8443/devops/backend", expected: "gitlab.acme.corp/devops/backend"},
		{name: "query params and fragment stripped", input: "https://gitlab.com/devops/backend.git?ref=main#readme", expected: "gitlab.com/devops/backend"},
		{name: "wildcard preserved", input: "devops/*", expected: "devops/*"},
		{name: "double wildcard preserved", input: "devops/**", expected: "devops/**"},
		{name: "url with wildcard", input: "https://gitlab.com/acme/*", expected: "gitlab.com/acme/*"},
		{name: "kubernetes namespace", input: "kube-system", expected: "kube-system"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NormalizeNamespace(tt.input)
			if actual != tt.expected {
				t.Errorf("NormalizeNamespace(%q) = %q, want %q", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestScope_HierarchicalNamespaceMatching(t *testing.T) {
	// 1. Plain group "devops" authorizes root and all descendants, but rejects prefix collisions
	scopeDevops := &Scope{
		Namespaces: []string{"devops"},
	}

	// Root authorized
	if !scopeDevops.IsNamespaceAllowed("devops") {
		t.Error("expected 'devops' to authorize root group 'devops'")
	}
	// Descendants authorized
	if !scopeDevops.IsNamespaceAllowed("devops/backend") {
		t.Error("expected 'devops' to authorize descendant 'devops/backend'")
	}
	if !scopeDevops.IsNamespaceAllowed("devops/backend/service") {
		t.Error("expected 'devops' to authorize deep descendant 'devops/backend/service'")
	}
	if !scopeDevops.IsNamespaceAllowed("https://gitlab.com/devops/backend/service.git") {
		t.Error("expected 'devops' to authorize URL descendant 'https://gitlab.com/devops/backend/service.git'")
	}
	if !scopeDevops.IsNamespaceAllowed("git@gitlab.com:devops/backend.git") {
		t.Error("expected 'devops' to authorize SCP descendant 'git@gitlab.com:devops/backend.git'")
	}

	// Prefix collision rejection (security boundary)
	disallowedDevops := []string{
		"devops-tools",
		"devops_infra",
		"devops-prod",
		"other/devops",
		"my-devops/service",
		"https://gitlab.com/devops-tools/repo",
	}
	for _, target := range disallowedDevops {
		if scopeDevops.IsNamespaceAllowed(target) {
			t.Errorf("expected target %q to be disallowed by 'devops'", target)
		}
	}

	// 2. Trailing wildcard "devops/*" authorizes root and all descendants
	scopeWildcard := &Scope{
		Namespaces: []string{"devops/*"},
	}
	if !scopeWildcard.IsNamespaceAllowed("devops") {
		t.Error("expected 'devops/*' to authorize root group 'devops'")
	}
	if !scopeWildcard.IsNamespaceAllowed("devops/infra") {
		t.Error("expected 'devops/*' to authorize 'devops/infra'")
	}
	if !scopeWildcard.IsNamespaceAllowed("devops/infra/terraform") {
		t.Error("expected 'devops/*' to authorize deep descendant 'devops/infra/terraform'")
	}
	if scopeWildcard.IsNamespaceAllowed("devops-tools") {
		t.Error("expected 'devops/*' to disallow prefix collision 'devops-tools'")
	}
	if scopeWildcard.IsNamespaceAllowed("devops_infra") {
		t.Error("expected 'devops/*' to disallow prefix collision 'devops_infra'")
	}

	// 3. Domain qualified group "gitlab.com/acme/*"
	scopeDomain := &Scope{
		Namespaces: []string{"gitlab.com/acme/*"},
	}
	if !scopeDomain.IsNamespaceAllowed("gitlab.com/acme") {
		t.Error("expected 'gitlab.com/acme/*' to authorize root 'gitlab.com/acme'")
	}
	if !scopeDomain.IsNamespaceAllowed("gitlab.com/acme/project-1") {
		t.Error("expected 'gitlab.com/acme/*' to authorize 'gitlab.com/acme/project-1'")
	}
	if !scopeDomain.IsNamespaceAllowed("https://gitlab.com/acme/project-1.git") {
		t.Error("expected 'gitlab.com/acme/*' to authorize URL 'https://gitlab.com/acme/project-1.git'")
	}
	if !scopeDomain.IsNamespaceAllowed("https://gitlab.com:8443/acme/subgroup/project-2") {
		t.Error("expected 'gitlab.com/acme/*' to authorize URL with port")
	}
	// Different domain should fail
	if scopeDomain.IsNamespaceAllowed("github.com/acme/project-1") {
		t.Error("expected 'gitlab.com/acme/*' to disallow 'github.com/acme/project-1'")
	}
	// Prefix collision on domain group should fail
	if scopeDomain.IsNamespaceAllowed("gitlab.com/acme-corp/project-1") {
		t.Error("expected 'gitlab.com/acme/*' to disallow prefix collision 'gitlab.com/acme-corp/project-1'")
	}

	// 4. Wildcard domain namespace pattern "*.internal/devops/*"
	scopeWildcardDomain := &Scope{
		Namespaces: []string{"*.internal/devops/*"},
	}
	if !scopeWildcardDomain.IsNamespaceAllowed("https://gitlab.internal/devops/repo") {
		t.Error("expected '*.internal/devops/*' to authorize 'gitlab.internal/devops/repo'")
	}
	if !scopeWildcardDomain.IsNamespaceAllowed("https://internal/devops/repo") {
		t.Error("expected '*.internal/devops/*' to authorize apex 'internal/devops/repo'")
	}
	if scopeWildcardDomain.IsNamespaceAllowed("https://evil.corp/devops/repo") {
		t.Error("expected '*.internal/devops/*' to disallow 'evil.corp/devops/repo'")
	}

	// 5. Universal wildcard "*" authorizes everything
	scopeUniversal := &Scope{
		Namespaces: []string{"*"},
	}
	if !scopeUniversal.IsNamespaceAllowed("any-group/any-repo") {
		t.Error("expected '*' to authorize any namespace")
	}
}

func TestValidator_HierarchicalNamespaceEnforcement(t *testing.T) {
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
			Namespaces: []string{"devops/*"},
		},
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Root group namespace -> SUCCESS
	vRoot, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentNamespace("devops"),
	)
	if _, err := vRoot.Verify(token); err != nil {
		t.Errorf("expected root group 'devops' to verify, got: %v", err)
	}

	// 2. Full URL with git clone syntax -> SUCCESS
	vURL, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentNamespace("https://gitlab.com/devops/backend/service.git"),
	)
	if _, err := vURL.Verify(token); err != nil {
		t.Errorf("expected URL namespace to verify, got: %v", err)
	}

	// 3. Deeper subgroup -> SUCCESS
	vSubgroup, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentNamespace("devops/core/auth/tokens"),
	)
	if _, err := vSubgroup.Verify(token); err != nil {
		t.Errorf("expected subgroup namespace to verify, got: %v", err)
	}

	// 4. Prefix collision ("devops-tools") -> FAIL with ErrScopeMismatch
	vDisallowed, _ := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentNamespace("devops-tools/repo"),
	)
	_, err = vDisallowed.Verify(token)
	if err == nil || !errors.Is(err, ErrScopeMismatch) {
		t.Errorf("expected ErrScopeMismatch for 'devops-tools/repo', got: %v", err)
	}
}

func TestScope_WildcardSlashIsolation(t *testing.T) {
	t.Parallel()

	// 1. Single wildcard '*' must NOT match across path boundaries
	scope := &Scope{
		Namespaces: []string{"*-audit"},
	}

	// Legitimate single-segment / root match
	if !scope.IsNamespaceAllowed("corp-audit") {
		t.Error("expected '*-audit' to match single-segment 'corp-audit'")
	}
	if !scope.IsNamespaceAllowed("sec-audit") {
		t.Error("expected '*-audit' to match single-segment 'sec-audit'")
	}

	// Legitimate descendants of authorized root
	if !scope.IsNamespaceAllowed("corp-audit/project-x") {
		t.Error("expected '*-audit' to authorize descendant 'corp-audit/project-x'")
	}
	if !scope.IsNamespaceAllowed("corp-audit/subgroup/project-y") {
		t.Error("expected '*-audit' to authorize deep descendant 'corp-audit/subgroup/project-y'")
	}

	// UNAUTHORIZED: Nested targets must NOT match if root is not authorized
	unauthorizedTargets := []string{
		"attacker/unauthorized/corp-audit",
		"attacker/corp-audit",
		"other-tenant/corp-audit",
		"gitlab.com/attacker/unauthorized/corp-audit",
		"gitlab.com/attacker/corp-audit",
	}
	for _, target := range unauthorizedTargets {
		if scope.IsNamespaceAllowed(target) {
			t.Errorf("SECURITY VULNERABILITY: '*-audit' unexpectedly authorized slash-spanning nested target %q", target)
		}
	}

	// 2. Multi-segment pattern boundaries (e.g. "team-*/backend")
	scopeMulti := &Scope{
		Namespaces: []string{"team-*/backend"},
	}
	if !scopeMulti.IsNamespaceAllowed("team-alpha/backend") {
		t.Error("expected 'team-*/backend' to match 'team-alpha/backend'")
	}
	if !scopeMulti.IsNamespaceAllowed("team-alpha/backend/service") {
		t.Error("expected 'team-*/backend' to authorize descendant 'team-alpha/backend/service'")
	}

	unauthorizedMulti := []string{
		"attacker/team-alpha/backend",
		"team-alpha/other/backend",
		"team-alpha/extra/path/backend",
		"other/team-beta/backend",
	}
	for _, target := range unauthorizedMulti {
		if scopeMulti.IsNamespaceAllowed(target) {
			t.Errorf("SECURITY VULNERABILITY: 'team-*/backend' unexpectedly authorized %q", target)
		}
	}

	// 3. Custom scope dimension and environment slash isolation
	claimsEnv := Claims{
		Scope: &Scope{
			Environments: []string{"*-prod"},
		},
	}
	if !claimsEnv.IsInScope("env", "corp-prod") {
		t.Error("expected '*-prod' to match 'corp-prod'")
	}
	if claimsEnv.IsInScope("env", "attacker/corp-prod") {
		t.Error("SECURITY VULNERABILITY: '*-prod' unexpectedly matched 'attacker/corp-prod'")
	}

	claimsCustom := Claims{
		Scope: &Scope{
			Custom: map[string][]string{
				"tier": {"*-enterprise"},
			},
		},
	}
	if !claimsCustom.IsInScope("tier", "gold-enterprise") {
		t.Error("expected '*-enterprise' to match 'gold-enterprise'")
	}
	if claimsCustom.IsInScope("tier", "attacker/gold-enterprise") {
		t.Error("SECURITY VULNERABILITY: '*-enterprise' unexpectedly matched 'attacker/gold-enterprise'")
	}
}

func TestScope_GlobstarRecursiveWildcard(t *testing.T) {
	t.Parallel()

	// 1. Leading globstar '**/corp-audit'
	scopeLeading := &Scope{
		Namespaces: []string{"**/corp-audit"},
	}
	if !scopeLeading.IsNamespaceAllowed("corp-audit") {
		t.Error("expected '**/corp-audit' to match apex 'corp-audit'")
	}
	if !scopeLeading.IsNamespaceAllowed("org/corp-audit") {
		t.Error("expected '**/corp-audit' to match 'org/corp-audit'")
	}
	if !scopeLeading.IsNamespaceAllowed("org/team/corp-audit") {
		t.Error("expected '**/corp-audit' to match 'org/team/corp-audit'")
	}
	if !scopeLeading.IsNamespaceAllowed("org/team/corp-audit/project-1") {
		t.Error("expected '**/corp-audit' to authorize descendant 'org/team/corp-audit/project-1'")
	}
	if scopeLeading.IsNamespaceAllowed("org/team/other-audit") {
		t.Error("expected '**/corp-audit' to NOT match 'org/team/other-audit'")
	}

	// 2. Middle globstar 'acme/**/backend'
	scopeMiddle := &Scope{
		Namespaces: []string{"acme/**/backend"},
	}
	if !scopeMiddle.IsNamespaceAllowed("acme/backend") {
		t.Error("expected 'acme/**/backend' to match zero-segment 'acme/backend'")
	}
	if !scopeMiddle.IsNamespaceAllowed("acme/infra/backend") {
		t.Error("expected 'acme/**/backend' to match 'acme/infra/backend'")
	}
	if !scopeMiddle.IsNamespaceAllowed("acme/infra/sub/backend") {
		t.Error("expected 'acme/**/backend' to match 'acme/infra/sub/backend'")
	}
	if scopeMiddle.IsNamespaceAllowed("attacker/acme/infra/backend") {
		t.Error("expected 'acme/**/backend' to NOT match 'attacker/acme/infra/backend'")
	}
	if scopeMiddle.IsNamespaceAllowed("acme/infra/frontend") {
		t.Error("expected 'acme/**/backend' to NOT match 'acme/infra/frontend'")
	}
}
