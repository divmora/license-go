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
		{
			name:  "invalid entries and empty key skipped",
			input: "tier=platinum;invalid;=value;   ",
			expected: map[string][]string{
				"tier": {"platinum"},
			},
		},
		{
			name:     "all invalid returns nil",
			input:    "invalid_entry_no_equals",
			expected: nil,
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

func TestParseMetadata(t *testing.T) {
	if m := parseMetadata(""); len(m) != 0 {
		t.Errorf("expected empty map for empty string, got %v", m)
	}

	m := parseMetadata("k1=v1,k2=v2,invalid,=val,  ")
	if m["k1"] != "v1" || m["k2"] != "v2" {
		t.Errorf("expected k1=v1 and k2=v2, got %v", m)
	}
	if len(m) != 2 {
		t.Errorf("expected length 2, got %d", len(m))
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
	if err := runCLI([]string{"release", "unknown-sub"}); err == nil {
		t.Errorf("expected error for unknown release subcommand")
	}
	if err := runCLI([]string{"key", "unknown-sub"}); err == nil {
		t.Errorf("expected error for unknown key subcommand")
	}
	if err := runCLI([]string{"bsl", "unknown-sub"}); err == nil {
		t.Errorf("expected error for unknown bsl subcommand")
	}
}

func TestCLI_FingerprintSubcommand(t *testing.T) {
	// 1. Default fingerprint output
	if err := runFingerprint([]string{}); err != nil {
		t.Fatalf("runFingerprint failed: %v", err)
	}

	// 2. JSON fingerprint output
	if err := runFingerprint([]string{"-json"}); err != nil {
		t.Fatalf("runFingerprint with -json failed: %v", err)
	}

	// 3. Specific platform: host
	if err := runFingerprint([]string{"-platform", "host"}); err != nil {
		t.Fatalf("runFingerprint with -platform host failed: %v", err)
	}

	// 4. Invalid platform returns error
	if err := runFingerprint([]string{"-platform", "nonexistent"}); err == nil {
		t.Error("expected error for invalid platform, got nil")
	}

	// 5. Via runCLI dispatcher
	if err := runCLI([]string{"fingerprint"}); err != nil {
		t.Fatalf("runCLI fingerprint failed: %v", err)
	}
	if err := runCLI([]string{"fingerprint", "-json"}); err != nil {
		t.Fatalf("runCLI fingerprint -json failed: %v", err)
	}
}

func TestCLI_RequestSubcommand(t *testing.T) {
	tmpDir := t.TempDir()
	reqPath := filepath.Join(tmpDir, "test.divreq")
	privKeyPath := filepath.Join(tmpDir, "priv.pem")
	pubKeyPath := filepath.Join(tmpDir, "pub.pem")
	licPath := filepath.Join(tmpDir, "fulfilled.key")

	// Keygen first
	if err := runKeygen([]string{"-out-dir", tmpDir, "-priv-name", "priv.pem", "-pub-name", "pub.pem"}); err != nil {
		t.Fatal(err)
	}

	// 1. Missing customer
	if err := runRequest([]string{"-product", "gitlab-fleet-governor"}); err == nil {
		t.Error("expected error for missing customer")
	}

	// 2. Missing product
	if err := runRequest([]string{"-customer", "Acme"}); err == nil {
		t.Error("expected error for missing product")
	}

	// 3. Unknown platform
	if err := runRequest([]string{"-customer", "Acme", "-product", "test", "-platform", "invalid"}); err == nil {
		t.Error("expected error for invalid platform")
	}

	// 4. Valid request generated to file
	err := runRequest([]string{
		"-customer", "Acme Corporation",
		"-product", "gitlab-fleet-governor",
		"-plan", "enterprise",
		"-features", "sso,audit-logs",
		"-limits", "max_nodes=10,max_runners=50",
		"-notes", "air-gapped datacenter node",
		"-platform", "host",
		"-out", reqPath,
	})
	if err != nil {
		t.Fatalf("runRequest failed: %v", err)
	}

	// 5. Valid request stdout with JSON
	if err := runRequest([]string{"-customer", "Acme", "-product", "test", "-json"}); err != nil {
		t.Fatalf("runRequest with -json failed: %v", err)
	}

	// 6. Fulfill the request using 'license issue -request'
	err = runIssue([]string{
		"-request", reqPath,
		"-private-key", privKeyPath,
		"-valid-days", "365",
		"-out", licPath,
	})
	if err != nil {
		t.Fatalf("runIssue fulfilling request failed: %v", err)
	}

	// 7. Verify the issued license matches the requested fingerprint and attributes
	err = runVerify([]string{
		"-public-key", pubKeyPath,
		"-license", licPath,
		"-product", "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("runVerify for license fulfilled from request failed: %v", err)
	}

	// 8. runCLI license request
	if err := runCLI([]string{"license", "request", "-customer", "Acme", "-product", "test"}); err != nil {
		t.Fatalf("runCLI license request failed: %v", err)
	}
	if err := runCLI([]string{"request", "-customer", "Acme", "-product", "test"}); err != nil {
		t.Fatalf("runCLI shortcut request failed: %v", err)
	}
}

func TestCLI_DispatchersAndErrorPaths(t *testing.T) {
	// 1. Empty args
	if err := runCLI([]string{}); err != nil {
		t.Errorf("expected nil for empty args, got %v", err)
	}

	// 2. Global help commands
	for _, h := range []string{"help", "-h", "--help", "-help"} {
		if err := runCLI([]string{h}); err != nil {
			t.Errorf("expected nil for %s, got %v", h, err)
		}
	}

	// 3. Unknown top-level command
	if err := runCLI([]string{"unknown-cmd"}); err == nil {
		t.Error("expected error for unknown-cmd, got nil")
	}

	// 4. Domain group help and unknown subcommands
	groups := []string{"license", "lic", "release", "rel", "key", "keys", "bsl"}
	for _, g := range groups {
		// Group with no subargs -> prints usage and returns nil
		if err := runCLI([]string{g}); err != nil {
			t.Errorf("expected nil for empty group %s, got %v", g, err)
		}
		// Group with help -> returns nil
		if err := runCLI([]string{g, "help"}); err != nil {
			t.Errorf("expected nil for %s help, got %v", g, err)
		}
		// Group with unknown subcommand -> returns error
		if err := runCLI([]string{g, "unknown-sub"}); err == nil {
			t.Errorf("expected error for %s unknown-sub, got nil", g)
		}
	}

	// 5. SignRelease error branches
	if err := runSignRelease([]string{}); err == nil {
		t.Error("expected error for runSignRelease with no flags")
	}
	if err := runSignRelease([]string{"-private-key", "some-key"}); err == nil {
		t.Error("expected error for runSignRelease missing product")
	}
	if err := runSignRelease([]string{"-private-key", "some-key", "-product", "test"}); err == nil {
		t.Error("expected error for runSignRelease missing version")
	}

	// 6. InspectRelease error branches
	if err := runInspectRelease([]string{}); err == nil {
		t.Error("expected error for runInspectRelease with no attestation")
	}

	// 7. Keygen error handling with invalid output directory
	if err := runKeygen([]string{"-out-dir", "/dev/null/impossible"}); err == nil {
		t.Error("expected error for runKeygen with invalid dir")
	}
}

func TestCLI_ShortcutsAndGroupCommands(t *testing.T) {
	tmpDir := t.TempDir()

	// Direct shortcuts
	shortcuts := [][]string{
		{"fingerprint"},
		{"issue"},
		{"verify"},
		{"inspect"},
		{"status"},
		{"request"},
		{"keygen", "-out-dir", tmpDir},
		{"keyring"},
		{"sign-release"},
		{"verify-release"},
		{"inspect-release"},
		{"bsl-eval"},
	}
	for _, sc := range shortcuts {
		_ = runCLI(sc)
	}

	// Group dispatchers
	groupCmds := [][]string{
		{"license", "issue"},
		{"license", "verify"},
		{"license", "inspect"},
		{"license", "status"},
		{"license", "request"},
		{"release", "sign"},
		{"release", "sign-release"},
		{"release", "verify"},
		{"release", "verify-release"},
		{"release", "inspect"},
		{"release", "inspect-release"},
		{"key", "gen", "-out-dir", tmpDir},
		{"key", "generate", "-out-dir", tmpDir},
		{"key", "keygen", "-out-dir", tmpDir},
		{"key", "inspect"},
		{"key", "ring"},
		{"key", "keyring"},
		{"bsl", "eval"},
		{"bsl", "evaluate"},
		{"bsl", "bsl-eval"},
	}
	for _, gc := range groupCmds {
		_ = runCLI(gc)
	}
}

func TestCLI_StatusDetailed(t *testing.T) {
	tmpDir := t.TempDir()
	pubKeyPath := filepath.Join(tmpDir, "pub.pem")
	privKeyPath := filepath.Join(tmpDir, "priv.pem")
	licPath := filepath.Join(tmpDir, "license.key")

	if err := runKeygen([]string{"-out-dir", tmpDir, "-priv-name", "priv.pem", "-pub-name", "pub.pem"}); err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}

	if err := runIssue([]string{
		"-customer", "Acme Corp",
		"-product", "gitlab-fleet-governor",
		"-private-key", privKeyPath,
		"-plan", "enterprise",
		"-features", "sso,ha",
		"-limits", "max_nodes=50,max_runners=100",
		"-out", licPath,
	}); err != nil {
		t.Fatalf("runIssue failed: %v", err)
	}

	// 1. Full verification path with all options toggled
	err := runStatus([]string{
		"-license", licPath,
		"-public-key", pubKeyPath,
		"-product", "gitlab-fleet-governor",
		"-usage", "max_nodes=10,max_runners=20",
		"-title", "ACME SYSTEM STATUS",
		"-compact",
		"-no-quotas",
		"-no-features",
		"-no-scopes",
		"-no-provenance",
	})
	if err != nil {
		t.Fatalf("runStatus full verified failed: %v", err)
	}

	// 2. Unverified fallback inspection (no public key passed)
	err = runStatus([]string{
		"-license", licPath,
		"-usage", "max_nodes=5",
	})
	if err != nil {
		t.Fatalf("runStatus fallback inspection failed: %v", err)
	}

	// 3. Status with missing license
	err = runStatus([]string{"-license", filepath.Join(tmpDir, "non_existent.key")})
	if err == nil {
		t.Error("expected error for non-existent license in runStatus")
	}
}

func TestCLI_SignAndInspectReleaseComprehensive(t *testing.T) {
	tmpDir := t.TempDir()
	pubKeyPath := filepath.Join(tmpDir, "pub.pem")
	privKeyPath := filepath.Join(tmpDir, "priv.pem")
	relPath := filepath.Join(tmpDir, "release.sig")
	relCompactPath := filepath.Join(tmpDir, "release.compact")

	if err := runKeygen([]string{"-out-dir", tmpDir, "-priv-name", "priv.pem", "-pub-name", "pub.pem"}); err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}

	// 1. Error: missing private key file
	if err := runSignRelease([]string{"-private-key", filepath.Join(tmpDir, "missing.pem"), "-product", "test", "-version", "v1.0.0"}); err == nil {
		t.Error("expected error for missing private key file")
	}

	// 2. Error: invalid build-date
	if err := runSignRelease([]string{"-private-key", privKeyPath, "-product", "test", "-version", "v1.0.0", "-build-date", "invalid"}); err == nil {
		t.Error("expected error for invalid build date")
	}

	// 3. Error: invalid release-date
	if err := runSignRelease([]string{"-private-key", privKeyPath, "-product", "test", "-version", "v1.0.0", "-release-date", "invalid"}); err == nil {
		t.Error("expected error for invalid release date")
	}

	// 4. Error: missing binary
	if err := runSignRelease([]string{"-private-key", privKeyPath, "-product", "test", "-version", "v1.0.0", "-binary", filepath.Join(tmpDir, "nonexistent")}); err == nil {
		t.Error("expected error for missing binary path")
	}

	// 5. Successful sign-release with file output and dates
	err := runSignRelease([]string{
		"-private-key", privKeyPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v1.0.0",
		"-build-date", "2026-01-01",
		"-release-date", "2026-01-01",
		"-digest", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"-key-id", "rel-key-1",
		"-meta", "ci=github-actions,builder=docker",
		"-out", relPath,
	})
	if err != nil {
		t.Fatalf("runSignRelease failed: %v", err)
	}

	// 6. Successful sign-release compact to file
	err = runSignRelease([]string{
		"-private-key", privKeyPath,
		"-product", "gitlab-fleet-governor",
		"-version", "v1.0.0",
		"-armored=false",
		"-out", relCompactPath,
	})
	if err != nil {
		t.Fatalf("runSignRelease compact failed: %v", err)
	}

	// 7. Successful inspect-release with -attestation and -json
	if err := runInspectRelease([]string{"-attestation", relPath, "-json"}); err != nil {
		t.Fatalf("runInspectRelease with -json failed: %v", err)
	}

	// 8. Successful inspect-release with positional argument
	if err := runInspectRelease([]string{relPath}); err != nil {
		t.Fatalf("runInspectRelease positional failed: %v", err)
	}

	// 9. Inspect-release with invalid token
	if err := runInspectRelease([]string{"-attestation", "invalid-token"}); err == nil {
		t.Error("expected error for invalid release token in inspect")
	}

	// 10. Verify release
	if err := runVerifyRelease([]string{"-attestation", relPath, "-public-key", pubKeyPath, "-product", "gitlab-fleet-governor", "-version", "v1.0.0"}); err != nil {
		t.Fatalf("runVerifyRelease failed: %v", err)
	}
}

func TestCLI_VerifyEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	// Invalid public key format
	if err := runVerify([]string{"-public-key", "invalid-key-data", "-license", "token"}); err == nil {
		t.Error("expected error for invalid public key data in runVerify")
	}

	// Missing public key when no env set
	t.Setenv("DIVMORA_PUBLIC_KEY", "")
	t.Setenv("DIVMORA_PUBLIC_KEYS_PEM", "")
	t.Setenv("DIVMORA_PUBLIC_KEY_FILE", filepath.Join(tmpDir, "missing.pem"))
	if err := runVerify([]string{"-license", "token"}); err == nil {
		t.Error("expected error for missing public key in runVerify")
	}
}

func TestCLI_VerifyReleaseEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing attestation
	if err := runVerifyRelease([]string{}); err == nil {
		t.Error("expected error for missing attestation in runVerifyRelease")
	}

	// 2. Invalid public key format
	if err := runVerifyRelease([]string{"-attestation", "token", "-public-key", "invalid-key"}); err == nil {
		t.Error("expected error for invalid public key in runVerifyRelease")
	}

	// 3. Missing public key when no env set
	t.Setenv("DIVMORA_PUBLIC_KEY", "")
	t.Setenv("DIVMORA_PUBLIC_KEYS_PEM", "")
	t.Setenv("DIVMORA_PUBLIC_KEY_FILE", filepath.Join(tmpDir, "missing.pem"))
	if err := runVerifyRelease([]string{"-attestation", "token"}); err == nil {
		t.Error("expected error for missing public key in runVerifyRelease")
	}
}

func TestCLI_BSLEvalAndInspectAndFingerprintEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	pubKeyPath := filepath.Join(tmpDir, "pub.pem")
	privKeyPath := filepath.Join(tmpDir, "priv.pem")
	licPath := filepath.Join(tmpDir, "test.lic")

	_ = runKeygen([]string{"-out-dir", tmpDir, "-priv-name", "priv.pem", "-pub-name", "pub.pem"})
	_ = runIssue([]string{
		"-customer", "Acme",
		"-product", "test-product",
		"-private-key", privKeyPath,
		"-out", licPath,
	})

	// 1. runFingerprint with -quiet, -platform host, and invalid platform
	if err := runFingerprint([]string{"-quiet"}); err != nil {
		t.Errorf("runFingerprint -quiet failed: %v", err)
	}
	if err := runFingerprint([]string{"-platform", "host"}); err != nil {
		t.Errorf("runFingerprint -platform host failed: %v", err)
	}
	if err := runFingerprint([]string{"-platform", "invalid-platform"}); err == nil {
		t.Error("expected error for invalid platform in runFingerprint")
	}

	// 2. runInspect with -json, env-loaded license, and error cases
	if err := runInspect([]string{"-license", licPath, "-json"}); err != nil {
		t.Errorf("runInspect with -json failed: %v", err)
	}
	data, _ := os.ReadFile(licPath)
	t.Setenv("DIVMORA_LICENSE_KEY", string(data))
	if err := runInspect([]string{}); err != nil {
		t.Errorf("runInspect with DIVMORA_LICENSE_KEY failed: %v", err)
	}
	t.Setenv("DIVMORA_LICENSE_KEY", "")
	t.Setenv("DIVMORA_LICENSE_FILE", "")
	if err := runInspect([]string{}); err == nil {
		t.Error("expected error for runInspect without license")
	}
	if err := runInspect([]string{"-license", "invalid.token"}); err == nil {
		t.Error("expected error for runInspect with invalid token")
	}

	// 3. runBSLEval error branches and flags
	if err := runBSLEval([]string{"-release-date", "invalid-date"}); err == nil {
		t.Error("expected error for invalid release-date in runBSLEval")
	}
	if err := runBSLEval([]string{"-release-date", "2026-01-01", "-change-date", "invalid-date"}); err == nil {
		t.Error("expected error for invalid change-date in runBSLEval")
	}
	if err := runBSLEval([]string{"-release-date", "2026-01-01", "-time", "invalid-time"}); err == nil {
		t.Error("expected error for invalid time in runBSLEval")
	}
	// Authorized BSL evaluation
	err := runBSLEval([]string{
		"-release-date", "2026-01-01",
		"-change-date", "2029-01-01",
		"-product", "test-product",
		"-env", "staging",
		"-usage", "nodes=5",
		"-features", "metrics",
		"-free-limits", "nodes=10",
		"-exempt-envs", "staging",
		"-excluded-features", "sso",
		"-dry-run",
		"-simulation",
		"-json",
	})
	if err != nil {
		t.Errorf("runBSLEval authorized evaluation failed: %v", err)
	}

	// Unauthorized BSL evaluation returns error
	err = runBSLEval([]string{
		"-release-date", "2026-01-01",
		"-product", "test-product",
		"-env", "production",
		"-features", "sso",
		"-excluded-features", "sso",
	})
	if err == nil {
		t.Error("expected error for unauthorized BSL evaluation")
	}

	_ = pubKeyPath
}

func TestCLI_IssueFlagsAndErrors(t *testing.T) {
	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "priv.pem")
	pubKeyPath := filepath.Join(tmpDir, "pub.pem")
	_ = runKeygen([]string{"-out-dir", tmpDir, "-priv-name", "priv.pem", "-pub-name", "pub.pem"})

	// 1. Missing private key
	if err := runIssue([]string{"-product", "test", "-customer", "Acme"}); err == nil {
		t.Error("expected error for missing private key in runIssue")
	}

	// 2. Missing product
	if err := runIssue([]string{"-private-key", privKeyPath, "-customer", "Acme"}); err == nil {
		t.Error("expected error for missing product in runIssue")
	}

	// 3. Missing customer
	if err := runIssue([]string{"-private-key", privKeyPath, "-product", "test"}); err == nil {
		t.Error("expected error for missing customer in runIssue")
	}

	// 4. Invalid request file
	if err := runIssue([]string{"-request", filepath.Join(tmpDir, "missing.divreq"), "-private-key", privKeyPath}); err == nil {
		t.Error("expected error for missing request file in runIssue")
	}

	// 5. Invalid private key file
	if err := runIssue([]string{"-private-key", filepath.Join(tmpDir, "missing.pem"), "-product", "test", "-customer", "Acme"}); err == nil {
		t.Error("expected error for missing private key file in runIssue")
	}

	// 6. Compact output with maintenance-days and allowed-versions (printed to stdout)
	err := runIssue([]string{
		"-private-key", privKeyPath,
		"-product", "test-prod",
		"-customer", "Acme",
		"-maintenance-days", "90",
		"-allowed-versions", "1.*,2.0.*",
		"-armored=false",
	})
	if err != nil {
		t.Fatalf("runIssue compact with maintenance days failed: %v", err)
	}

	_ = pubKeyPath
}
