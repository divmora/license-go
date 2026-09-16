package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func TestParseCustomScope(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name:     "empty",
			input:    "",
			expected: nil,
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: nil,
		},
		{
			name:  "single dimension single value",
			input: "tier=platinum",
			expected: map[string][]string{
				"tier": {"platinum"},
			},
		},
		{
			name:  "single dimension multiple values comma separated",
			input: "tier=platinum,gold",
			expected: map[string][]string{
				"tier": {"platinum", "gold"},
			},
		},
		{
			name:  "multiple dimensions semicolon separated with multiple values",
			input: "tier=platinum,gold;datacenter=dc-east,dc-west",
			expected: map[string][]string{
				"tier":       {"platinum", "gold"},
				"datacenter": {"dc-east", "dc-west"},
			},
		},
		{
			name:  "multiple dimensions comma separated when each is single val",
			input: "tier=gold,dc=dc-1",
			expected: map[string][]string{
				"tier": {"gold"},
				"dc":   {"dc-1"},
			},
		},
		{
			name:  "pipe separated values",
			input: "tier=gold|platinum;dc=dc-1|dc-2",
			expected: map[string][]string{
				"tier": {"gold", "platinum"},
				"dc":   {"dc-1", "dc-2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := parseCustomScope(tt.input)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("parseCustomScope(%q) = %+v, want %+v", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestCLI_IssueVerifyInspect_StandardAndCustomScopeAndMeta(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "private.pem")
	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	licensePath := filepath.Join(tmpDir, "test.license.key")

	// 1. Keygen
	err := runKeygen([]string{
		"-out-dir", tmpDir,
		"-priv-name", "private.pem",
		"-pub-name", "public.pem",
	})
	if err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}

	// 2. Issue with standard scopes, custom scopes, and metadata
	err = runIssue([]string{
		"-private-key", privKeyPath,
		"-customer", "Acme Corporation",
		"-email", "secops@acme.com",
		"-org-id", "org_acme_123",
		"-product", "gitlab-fleet-governor",
		"-plan", "enterprise",
		"-valid-days", "30",
		"-scope-envs", "production,staging",
		"-scope-accounts", "123456789012",
		"-scope-regions", "us-east-1,eu-west-1",
		"-scope-clusters", "prod-eks-01",
		"-scope-namespaces", "gitlab.com/acme/*",
		"-scope-hosts", "*.acme.corp",
		"-scope-custom", "tier=platinum,gold;datacenter=dc-east,dc-west",
		"-meta", "billing_id=inv-998,contact=admin@acme.com",
		"-out", licensePath,
		"-armored",
	})
	if err != nil {
		t.Fatalf("runIssue failed: %v", err)
	}

	// 3. Inspect (should parse without error, testing both standard terminal format and -json format)
	err = runInspect([]string{"-license", licensePath})
	if err != nil {
		t.Fatalf("runInspect failed: %v", err)
	}

	err = runInspect([]string{"-license", licensePath, "-json"})
	if err != nil {
		t.Fatalf("runInspect with -json failed: %v", err)
	}

	// 4. Verify - valid scopes and custom scope match
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-account", "123456789012",
		"-region", "us-east-1",
		"-cluster", "prod-eks-01",
		"-namespace", "gitlab.com/acme/project-1",
		"-host", "runner-01.acme.corp",
		"-custom-scope", "tier=platinum,datacenter=dc-east",
	})
	if err != nil {
		t.Fatalf("runVerify failed with matching scopes: %v", err)
	}

	// 5. Verify - apex domain with URL, port, and trailing path against *.acme.corp
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-account", "123456789012",
		"-region", "us-east-1",
		"-cluster", "prod-eks-01",
		"-namespace", "gitlab.com/acme/project-1",
		"-host", "https://acme.corp:8443/runners",
		"-custom-scope", "tier=platinum,datacenter=dc-east",
	})
	if err != nil {
		t.Fatalf("runVerify failed for apex domain URL: %v", err)
	}

	// 6. Verify - hierarchical URL namespace descendant match against "gitlab.com/acme/*"
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-account", "123456789012",
		"-region", "us-east-1",
		"-cluster", "prod-eks-01",
		"-namespace", "https://gitlab.com/acme/backend/service.git",
		"-host", "runner-01.acme.corp",
		"-custom-scope", "tier=platinum,datacenter=dc-east",
	})
	if err != nil {
		t.Fatalf("runVerify failed for hierarchical URL namespace descendant: %v", err)
	}

	// 7. Verify - root group namespace match against "gitlab.com/acme/*"
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-account", "123456789012",
		"-region", "us-east-1",
		"-cluster", "prod-eks-01",
		"-namespace", "gitlab.com/acme",
		"-host", "runner-01.acme.corp",
		"-custom-scope", "tier=platinum,datacenter=dc-east",
	})
	if err != nil {
		t.Fatalf("runVerify failed for root group namespace: %v", err)
	}

	// 8. Verify - namespace prefix collision should fail
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-account", "123456789012",
		"-region", "us-east-1",
		"-cluster", "prod-eks-01",
		"-namespace", "gitlab.com/acme-tools/repo",
		"-host", "runner-01.acme.corp",
		"-custom-scope", "tier=platinum,datacenter=dc-east",
	})
	if err == nil {
		t.Fatal("expected runVerify to fail for namespace prefix collision gitlab.com/acme-tools/repo, but succeeded")
	}

	// 9. Verify - custom scope mismatch should fail
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-custom-scope", "tier=bronze",
	})
	if err == nil {
		t.Fatal("expected runVerify to fail for custom scope tier=bronze, but succeeded")
	}

	// 10. Verify with authoritative server timestamp in HTTP Date format
	nowHTTPDate := time.Now().UTC().Format(time.RFC1123)
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-account", "123456789012",
		"-region", "us-east-1",
		"-cluster", "prod-eks-01",
		"-namespace", "gitlab.com/acme/project-1",
		"-host", "runner-01.acme.corp",
		"-custom-scope", "tier=platinum,datacenter=dc-east",
		"-authoritative-time", nowHTTPDate,
		"-max-skew", "1h",
	})
	if err != nil {
		t.Fatalf("runVerify with HTTP Date authoritative-time failed: %v", err)
	}

	// 11. Verify with strict-clock defense on tampered time should fail
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-env", "production",
		"-authoritative-time", "2020-01-01T00:00:00Z",
		"-max-skew", "5m",
		"-strict-clock",
	})
	if err == nil {
		t.Fatal("expected runVerify with -strict-clock to fail on tampered authoritative-time, but succeeded")
	}

	// 6. Direct claims verification for metadata
	resolved, err := license.ResolveLicense(licensePath)
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	claims, err := license.Inspect(resolved.Content)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if claims.Metadata["billing_id"] != "inv-998" {
		t.Errorf("expected metadata billing_id=inv-998, got %q", claims.Metadata["billing_id"])
	}
	if claims.Metadata["contact"] != "admin@acme.com" {
		t.Errorf("expected metadata contact=admin@acme.com, got %q", claims.Metadata["contact"])
	}
	if claims.Scope == nil {
		t.Fatal("expected claims.Scope to be non-nil")
	}
	if len(claims.Scope.Custom["tier"]) != 2 || claims.Scope.Custom["tier"][0] != "platinum" {
		t.Errorf("unexpected Scope.Custom['tier']: %+v", claims.Scope.Custom["tier"])
	}
}

func TestCLI_VerifyAndKeyringAutoResolveKeyRing(t *testing.T) {
	license.ResetVerificationKeyRing()
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "private.pem")
	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	licensePath := filepath.Join(tmpDir, "test.license.key")

	err := runKeygen([]string{
		"-out-dir", tmpDir,
		"-priv-name", "private.pem",
		"-pub-name", "public.pem",
	})
	if err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}

	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("ReadFile pubKeyPath failed: %v", err)
	}
	pubKey, err := license.ParsePublicKeyFromPEM(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM failed: %v", err)
	}
	pubB64 := license.EncodePublicKeyToBase64(pubKey)

	err = runIssue([]string{
		"-private-key", privKeyPath,
		"-customer", "Acme",
		"-product", "gitlab-fleet-governor",
		"-valid-days", "30",
		"-out", licensePath,
	})
	if err != nil {
		t.Fatalf("runIssue failed: %v", err)
	}

	// 1. Verify with DIVMORA_PUBLIC_KEY (base64) when -public-key is omitted
	t.Setenv(license.EnvPublicKeysPEM, "")
	t.Setenv(license.EnvPublicKey, pubB64)
	t.Setenv(license.EnvPublicKeyFile, "")
	err = runVerify([]string{
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("runVerify with DIVMORA_PUBLIC_KEY failed: %v", err)
	}

	// 2. Verify with DIVMORA_PUBLIC_KEYS_PEM (PEM bundle) when -public-key is omitted
	t.Setenv(license.EnvPublicKeysPEM, string(pubBytes))
	t.Setenv(license.EnvPublicKey, "")
	err = runVerify([]string{
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("runVerify with DIVMORA_PUBLIC_KEYS_PEM failed: %v", err)
	}

	// 3. Keyring auto-resolve from DIVMORA_PUBLIC_KEYS_PEM when args omitted
	err = runKeyring([]string{})
	if err != nil {
		t.Fatalf("runKeyring auto-resolve failed: %v", err)
	}

	// 4. Verify fails with informative error when neither -public-key nor env is set
	t.Setenv(license.EnvPublicKeysPEM, "")
	t.Setenv(license.EnvPublicKey, "")
	t.Setenv(license.EnvPublicKeyFile, "")
	err = runVerify([]string{
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
	})
	if err == nil {
		t.Fatal("expected runVerify to fail when no public key is provided")
	}

	// 5. Keyring fails with usage error when neither args nor env is set
	err = runKeyring([]string{})
	if err == nil {
		t.Fatal("expected runKeyring to fail when no public key is provided")
	}
}

func TestCLI_SignVerifyInspectRelease(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "private.pem")
	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	attestationPath := filepath.Join(tmpDir, "release.sig")
	binaryPath := filepath.Join(tmpDir, "app-binary")
	licensePath := filepath.Join(tmpDir, "app.license.key")

	// 1. Keygen
	err := runKeygen([]string{
		"-out-dir", tmpDir,
		"-priv-name", "private.pem",
		"-pub-name", "public.pem",
	})
	if err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}

	// 2. Dummy binary executable
	origBinaryBytes := []byte("#!/usr/bin/env bash\necho 'running release binary'\n")
	if err := os.WriteFile(binaryPath, origBinaryBytes, 0755); err != nil {
		t.Fatalf("WriteFile binary failed: %v", err)
	}

	// 3. Sign Release
	err = runSignRelease([]string{
		"-private-key", privKeyPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v2.5.0",
		"-git-commit", "897f05812345",
		"-binary", binaryPath,
		"-authority", "divmora.com/release",
		"-key-id", "rel-2026",
		"-meta", "builder=drone-ci",
		"-out", attestationPath,
		"-armored",
	})
	if err != nil {
		t.Fatalf("runSignRelease failed: %v", err)
	}

	// 4. Inspect Release
	err = runInspectRelease([]string{
		"-attestation", attestationPath,
	})
	if err != nil {
		t.Fatalf("runInspectRelease failed: %v", err)
	}

	err = runInspectRelease([]string{
		"-attestation", attestationPath,
		"-json",
	})
	if err != nil {
		t.Fatalf("runInspectRelease with -json failed: %v", err)
	}

	// 5. Verify Release
	err = runVerifyRelease([]string{
		"-public-key", pubKeyPath,
		"-attestation", attestationPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v2.5.0",
		"-git-commit", "897f05812345",
		"-binary", binaryPath,
	})
	if err != nil {
		t.Fatalf("runVerifyRelease failed: %v", err)
	}

	// 6. Verify Release with Tampered Binary Fails
	tamperedBinaryPath := filepath.Join(tmpDir, "tampered-binary")
	if err := os.WriteFile(tamperedBinaryPath, []byte("tampered content"), 0755); err != nil {
		t.Fatalf("WriteFile tampered binary failed: %v", err)
	}
	err = runVerifyRelease([]string{
		"-public-key", pubKeyPath,
		"-attestation", attestationPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v2.5.0",
		"-binary", tamperedBinaryPath,
	})
	if err == nil {
		t.Fatal("expected runVerifyRelease to fail on tampered binary")
	}

	// 7. Verify License with Provenance Integration
	err = runIssue([]string{
		"-private-key", privKeyPath,
		"-customer", "Acme Enterprise",
		"-product", "gitlab-fleet-governor",
		"-valid-days", "30",
		"-out", licensePath,
	})
	if err != nil {
		t.Fatalf("runIssue failed: %v", err)
	}

	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-version", "v2.5.0",
		"-git-commit", "897f05812345",
		"-binary", binaryPath,
		"-release-attestation", attestationPath,
		"-require-release-attestation",
	})
	if err != nil {
		t.Fatalf("runVerify with release attestation failed: %v", err)
	}
}
