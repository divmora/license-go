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

func TestCLI_StatusSubcommand(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "private.pem")
	pubKeyPath := filepath.Join(tmpDir, "public.pem")
	licensePath := filepath.Join(tmpDir, "status.license.key")

	// 1. Keygen
	err := runKeygen([]string{
		"-out-dir", tmpDir,
		"-priv-name", "private.pem",
		"-pub-name", "public.pem",
	})
	if err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}

	// 2. Issue license with limits and features
	err = runIssue([]string{
		"-private-key", privKeyPath,
		"-customer", "Acme Corporation",
		"-org-id", "org_acme_status",
		"-product", "gitlab-fleet-governor",
		"-plan", "enterprise",
		"-valid-days", "30",
		"-features", "ha,audit-logs,auto-scaling",
		"-limits", "max_runners=200,max_nodes=10",
		"-scope-envs", "production",
		"-out", licensePath,
	})
	if err != nil {
		t.Fatalf("runIssue failed: %v", err)
	}

	// 3. Status with verified license and usage overlay
	err = runStatus([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-product", "gitlab-fleet-governor",
		"-usage", "max_runners=142,max_nodes=6",
		"-title", "FLEET GOVERNOR STATUS",
	})
	if err != nil {
		t.Fatalf("runStatus with usage failed: %v", err)
	}

	// 4. Compact status
	err = runStatus([]string{
		"-public-key", pubKeyPath,
		"-license", licensePath,
		"-compact",
	})
	if err != nil {
		t.Fatalf("runStatus with -compact failed: %v", err)
	}

	// 5. Status without public key (unverified claims fallback)
	err = runStatus([]string{
		"-license", licensePath,
	})
	if err != nil {
		t.Fatalf("runStatus unverified fallback failed: %v", err)
	}

	// 6. Status with environment variables auto-resolution
	licBytes, err := os.ReadFile(licensePath)
	if err != nil {
		t.Fatalf("ReadFile licensePath failed: %v", err)
	}
	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("ReadFile pubKeyPath failed: %v", err)
	}

	t.Setenv(license.EnvLicenseKey, string(licBytes))
	t.Setenv(license.EnvPublicKeysPEM, string(pubBytes))

	err = runStatus([]string{
		"-usage", "max_runners=50",
	})
	if err != nil {
		t.Fatalf("runStatus with auto-resolved env vars failed: %v", err)
	}
}

func TestCLI_BSLEvalSubcommand(t *testing.T) {
	// 1. Non-production exemption (staging)
	err := runBSLEval([]string{
		"-release-date", "2025-01-01",
		"-years", "3",
		"-env", "staging",
		"-product", "gitlab-fleet-governor",
		"-usage", "max_runners=500,max_nodes=100",
	})
	if err != nil {
		t.Fatalf("expected bsl-eval to succeed for staging environment, got: %v", err)
	}

	// 2. Production within free tier limits
	err = runBSLEval([]string{
		"-release-date", "2025-01-01",
		"-years", "3",
		"-env", "production",
		"-product", "gitlab-fleet-governor",
		"-free-limits", "max_nodes=10,max_runners=50",
		"-usage", "max_nodes=6,max_runners=20",
		"-features", "basic-ingest",
	})
	if err != nil {
		t.Fatalf("expected bsl-eval to succeed within free limits in production, got: %v", err)
	}

	// 3. Production exceeding free tier limits
	err = runBSLEval([]string{
		"-release-date", "2025-01-01",
		"-years", "3",
		"-env", "production",
		"-free-limits", "max_nodes=10,max_runners=50",
		"-usage", "max_nodes=25,max_runners=20",
	})
	if err == nil {
		t.Fatalf("expected bsl-eval to return error when exceeding free tier limits")
	}

	// 4. JSON output mode
	err = runBSLEval([]string{
		"-release-date", "2025-01-01",
		"-years", "3",
		"-env", "development",
		"-json",
	})
	if err != nil {
		t.Fatalf("expected bsl-eval with -json to succeed, got: %v", err)
	}

	// 5. Converted open source
	err = runBSLEval([]string{
		"-release-date", "2025-01-01",
		"-years", "3",
		"-time", "2029-01-01",
		"-env", "production",
		"-usage", "max_nodes=1000000",
	})
	if err != nil {
		t.Fatalf("expected bsl-eval to succeed after Change Date, got: %v", err)
	}
}

func TestCLI_DomainGroupedRouting(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "priv.pem")
	pubKeyPath := filepath.Join(tmpDir, "pub.pem")
	licPath := filepath.Join(tmpDir, "lic.key")
	relPath := filepath.Join(tmpDir, "release.divrel")

	// 1. Grouped key generation: 'key gen'
	err := runCLI([]string{"key", "gen", "-out-dir", tmpDir, "-priv-name", "priv.pem", "-pub-name", "pub.pem"})
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}

	// 2. Grouped key inspection: 'key inspect'
	err = runCLI([]string{"key", "inspect", pubKeyPath})
	if err != nil {
		t.Fatalf("key inspect failed: %v", err)
	}

	// 3. Grouped license issuance: 'license issue'
	err = runCLI([]string{
		"license", "issue",
		"-private-key", privKeyPath,
		"-customer", "Grouped Corp",
		"-product", "gitlab-fleet-governor",
		"-valid-days", "30",
		"-out", licPath,
	})
	if err != nil {
		t.Fatalf("license issue failed: %v", err)
	}

	// 4. Grouped license verification: 'license verify'
	err = runCLI([]string{
		"license", "verify",
		"-public-key", pubKeyPath,
		"-license", licPath,
		"-product", "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("license verify failed: %v", err)
	}

	// 5. Grouped license inspection: 'license inspect'
	err = runCLI([]string{
		"license", "inspect",
		"-license", licPath,
		"-json",
	})
	if err != nil {
		t.Fatalf("license inspect failed: %v", err)
	}

	// 6. Grouped license status: 'license status'
	err = runCLI([]string{
		"license", "status",
		"-public-key", pubKeyPath,
		"-license", licPath,
		"-compact",
	})
	if err != nil {
		t.Fatalf("license status failed: %v", err)
	}

	// 7. Grouped release attestation: 'release sign'
	err = runCLI([]string{
		"release", "sign",
		"-private-key", privKeyPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v1.0.0",
		"-out", relPath,
	})
	if err != nil {
		t.Fatalf("release sign failed: %v", err)
	}

	// 8. Grouped release verification: 'release verify'
	err = runCLI([]string{
		"release", "verify",
		"-public-key", pubKeyPath,
		"-attestation", relPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v1.0.0",
	})
	if err != nil {
		t.Fatalf("release verify failed: %v", err)
	}

	// 9. Grouped release inspection: 'release inspect'
	err = runCLI([]string{
		"release", "inspect",
		"-attestation", relPath,
		"-json",
	})
	if err != nil {
		t.Fatalf("release inspect failed: %v", err)
	}

	// 10. Grouped BSL evaluation: 'bsl eval'
	err = runCLI([]string{
		"bsl", "eval",
		"-release-date", "2025-01-01",
		"-years", "3",
		"-env", "staging",
	})
	if err != nil {
		t.Fatalf("bsl eval failed: %v", err)
	}

	// 11. Help commands should return nil error
	helpInvocations := [][]string{
		{},
		{"help"},
		{"license"},
		{"license", "help"},
		{"release"},
		{"release", "help"},
		{"key"},
		{"key", "help"},
		{"bsl"},
		{"bsl", "help"},
	}
	for _, h := range helpInvocations {
		if err := runCLI(h); err != nil {
			t.Fatalf("expected help for %v to succeed, got: %v", h, err)
		}
	}

	// 12. Invalid commands
	if err := runCLI([]string{"unknown-group"}); err == nil {
		t.Errorf("expected error for unknown group")
	}
	if err := runCLI([]string{"license", "unknown-sub"}); err == nil {
		t.Errorf("expected error for unknown license subcommand")
	}
}
