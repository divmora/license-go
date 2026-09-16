package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keypair: %v", err)
	}
	return pub, priv
}

func TestSignAndVerifyRelease_CompactAndArmored(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)
	if _, err := ring.AddKey(pub, WithCustomKeyID("key-release-2026")); err != nil {
		t.Fatalf("ring.AddKey failed: %v", err)
	}

	buildTime := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	releaseTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	claims := ReleaseClaims{
		Product:      "gitlab-fleet-governor",
		Version:      "v2.4.0",
		GitCommit:    "897f058123456789abcdef",
		BuildDate:    buildTime,
		ReleaseDate:  releaseTime,
		BinaryDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Authority:    "divmora.com/release",
		KeyID:        "key-release-2026",
		Metadata: map[string]string{
			"builder": "ci-runner-linux-amd64",
		},
	}

	// 1. Sign compact token
	compactToken, err := SignRelease(claims, priv, WithSignerKeyID("key-release-2026"))
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}
	if !strings.HasPrefix(compactToken, ProtocolPrefixRelease+".") {
		t.Fatalf("expected prefix %s, got %s", ProtocolPrefixRelease, compactToken)
	}

	// Verify compact token
	verifiedClaims, keyEntry, err := VerifyRelease(compactToken, ring)
	if err != nil {
		t.Fatalf("VerifyRelease failed: %v", err)
	}
	if verifiedClaims.Product != "gitlab-fleet-governor" || verifiedClaims.Version != "v2.4.0" {
		t.Fatalf("unexpected verified claims: %+v", verifiedClaims)
	}
	if keyEntry.ID != "key-release-2026" {
		t.Fatalf("expected key ID key-release-2026, got %s", keyEntry.ID)
	}

	// 2. Sign armored PEM block
	armoredPEM, err := SignReleaseArmored(claims, priv, WithSignerKeyID("key-release-2026"))
	if err != nil {
		t.Fatalf("SignReleaseArmored failed: %v", err)
	}
	if !strings.Contains(armoredPEM, "-----BEGIN "+PEMTypeReleaseAttestation+"-----") {
		t.Fatalf("expected armored PEM block, got:\n%s", armoredPEM)
	}

	// Verify armored PEM block
	verifiedArmored, _, err := VerifyRelease(armoredPEM, ring)
	if err != nil {
		t.Fatalf("VerifyRelease with armored PEM failed: %v", err)
	}
	if verifiedArmored.GitCommit != claims.GitCommit {
		t.Fatalf("expected git commit %s, got %s", claims.GitCommit, verifiedArmored.GitCommit)
	}

	// 3. Inspect release without keys
	inspected, err := InspectRelease(armoredPEM)
	if err != nil {
		t.Fatalf("InspectRelease failed: %v", err)
	}
	if inspected.Product != "gitlab-fleet-governor" {
		t.Fatalf("expected product gitlab-fleet-governor, got %s", inspected.Product)
	}

	// Inspect release from file
	tmpDir := t.TempDir()
	sigFile := filepath.Join(tmpDir, "release.sig")
	if err := os.WriteFile(sigFile, []byte(armoredPEM), 0644); err != nil {
		t.Fatalf("failed to write sig file: %v", err)
	}
	inspectedFile, err := InspectReleaseFromFile(sigFile)
	if err != nil {
		t.Fatalf("InspectReleaseFromFile failed: %v", err)
	}
	if inspectedFile.Version != "v2.4.0" {
		t.Fatalf("expected version v2.4.0, got %s", inspectedFile.Version)
	}

	// 4. Test FormatInspect
	formatted := inspected.FormatInspect()
	if !strings.Contains(formatted, "DIVMORA RELEASE ATTESTATION CLAIMS") ||
		!strings.Contains(formatted, "gitlab-fleet-governor") ||
		!strings.Contains(formatted, "ci-runner-linux-amd64") {
		t.Fatalf("unexpected FormatInspect output:\n%s", formatted)
	}
}

func TestEvaluateProvenance_SuccessMatching(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	binaryContent := []byte("#!/bin/sh\necho Divmora Application\n")
	expectedDigest := ComputeBytesDigest(binaryContent)

	buildTime := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	releaseTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	claims := ReleaseClaims{
		Product:      "otel-aws-log-processor",
		Version:      "v1.5.0",
		GitCommit:    "a1b2c3d4e5f678901234567890abcdef12345678",
		BuildDate:    buildTime,
		ReleaseDate:  releaseTime,
		BinaryDigest: expectedDigest,
		Authority:    "divmora.com/release",
	}

	token, err := SignRelease(claims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	// Match exact parameters
	params := ProvenanceParams{
		ExpectedProduct:    "otel-aws-log-processor",
		CurrentVersion:     "1.5.0",   // SemVer clean matching
		CurrentCommit:      "a1b2c3d", // Prefix short SHA matching
		CurrentBuildDate:   buildTime,
		CurrentReleaseDate: releaseTime,
		BinaryBytes:        binaryContent,
	}

	prov, err := EvaluateProvenance(token, ring, params)
	if err != nil {
		t.Fatalf("EvaluateProvenance failed: %v", err)
	}

	if !prov.Attested {
		t.Fatalf("expected prov.Attested to be true")
	}
	if !prov.DigestMatched {
		t.Fatalf("expected prov.DigestMatched to be true")
	}
	if prov.Tampered {
		t.Fatalf("expected prov.Tampered to be false, got: %s", prov.TamperReason)
	}
}

func TestEvaluateProvenance_TamperingScenarios(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	binaryContent := []byte("original binary content")
	digest := ComputeBytesDigest(binaryContent)

	baseClaims := ReleaseClaims{
		Product:      "gitlab-fleet-governor",
		Version:      "v2.0.0",
		GitCommit:    "1111222233334444555566667777888899990000",
		BuildDate:    time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC),
		ReleaseDate:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		BinaryDigest: digest,
	}

	token, err := SignRelease(baseClaims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	t.Run("Product mismatch", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct: "different-product",
			CurrentVersion:  "v2.0.0",
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "release attestation product does not match") {
			t.Fatalf("expected ErrReleaseProductMismatch, got: %v", err)
		}
	})

	t.Run("Version mismatch", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct: "gitlab-fleet-governor",
			CurrentVersion:  "v2.1.0",
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "release tampering detected") {
			t.Fatalf("expected release tampering error, got: %v", err)
		}
		var tamperErr *ReleaseTamperingError
		if !errors.As(err, &tamperErr) {
			t.Fatalf("expected *ReleaseTamperingError, got %T: %v", err, err)
		}
		if tamperErr.Field != "version" {
			t.Fatalf("expected field 'version', got: %s", tamperErr.Field)
		}
	})

	t.Run("Git commit mismatch", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct: "gitlab-fleet-governor",
			CurrentVersion:  "v2.0.0",
			CurrentCommit:   "999988887777",
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "release tampering detected") {
			t.Fatalf("expected release tampering error, got: %v", err)
		}
	})

	t.Run("Build date tampering", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct:  "gitlab-fleet-governor",
			CurrentVersion:   "v2.0.0",
			CurrentBuildDate: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), // >24h earlier than 2026-06-01
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "build date tampered") {
			t.Fatalf("expected build date tampering error, got: %v", err)
		}
	})

	t.Run("Release date tampering", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct:    "gitlab-fleet-governor",
			CurrentVersion:     "v2.0.0",
			CurrentReleaseDate: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // Claiming ancient release date
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "release date tampered") {
			t.Fatalf("expected release date tampering error, got: %v", err)
		}
	})

	t.Run("Binary digest tampering", func(t *testing.T) {
		tamperedBytes := []byte("tampered binary bytes")
		params := ProvenanceParams{
			ExpectedProduct: "gitlab-fleet-governor",
			CurrentVersion:  "v2.0.0",
			BinaryBytes:     tamperedBytes,
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "binary digest does not match") {
			t.Fatalf("expected digest mismatch error, got: %v", err)
		}
	})
}

func TestEvaluateProvenance_BSLConversionSpoofingDefeated(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	// Official release date: 2026-06-01
	officialReleaseDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	attestationClaims := ReleaseClaims{
		Product:     "gitlab-fleet-governor",
		Version:     "v1.0.0",
		ReleaseDate: officialReleaseDate,
		BuildDate:   officialReleaseDate,
	}

	attestationToken, err := SignRelease(attestationClaims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	// Attacker tries to configure ReleaseDate = 2020-01-01 in BSLPolicy
	// hoping to trick BSL into converting at 2026-06-01 (6 years later)
	forgedBSL := BSLPolicy{
		ReleaseDate:       time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		ChangePeriodYears: 3,
	}

	// 1. If forged release date is in policy, EvaluateProvenance flags tampering!
	val, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v1.0.0"),
		WithBSLPolicy(forgedBSL),
		WithReleaseAttestation(attestationToken),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	_, err = val.VerifyWithResultAt("", officialReleaseDate)
	if err == nil || !strings.Contains(err.Error(), "release date tampered") {
		t.Fatalf("expected release date tampering error, got: %v", err)
	}

	// 2. If policy doesn't tamper with CurrentReleaseDate, attestation enforces official ReleaseDate
	legitBSL := BSLPolicy{
		ReleaseDate:       officialReleaseDate,
		ChangePeriodYears: 3,
	}
	legitVal, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v1.0.0"),
		WithBSLPolicy(legitBSL),
		WithReleaseAttestation(attestationToken),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	// Evaluation at 2027-01-01 (before 3 years conversion): Must NOT be converted!
	evalTimeBefore := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	resBefore, err := legitVal.VerifyWithResultAt("", evalTimeBefore)
	if err != ErrLicenseNotFound {
		t.Fatalf("expected ErrLicenseNotFound before conversion, got: res=%v, err=%v", resBefore, err)
	}

	// Evaluation at 2029-06-02 (after 3 years from 2026-06-01): Converts legally!
	evalTimeAfter := time.Date(2029, 6, 2, 0, 0, 0, 0, time.UTC)
	resAfter, err := legitVal.VerifyWithResultAt("", evalTimeAfter)
	if err != nil {
		t.Fatalf("expected conversion after change date, got error: %v", err)
	}
	if !resAfter.BSLConverted {
		t.Fatalf("expected BSLConverted to be true")
	}
	if resAfter.EffectiveLicense != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0, got: %s", resAfter.EffectiveLicense)
	}
	if resAfter.Provenance == nil || !resAfter.Provenance.Attested {
		t.Fatalf("expected Provenance to be present and attested")
	}
}

func TestValidator_WithRequireReleaseAttestation(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	claims := Claims{
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Customer:  Customer{Name: "Acme Corp"},
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	lic, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Require attestation but missing
	valMissing, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithRequireReleaseAttestation(true),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	_, err = valMissing.Verify(lic)
	if err != ErrReleaseAttestationMissing {
		t.Fatalf("expected ErrReleaseAttestationMissing, got: %v", err)
	}

	// 2. Require attestation and valid
	relClaims := ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "v1.0.0",
		BuildDate: time.Now(),
	}
	attToken, err := SignRelease(relClaims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	valValid, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v1.0.0"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(attToken),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	res, err := valValid.VerifyWithResult(lic)
	if err != nil {
		t.Fatalf("VerifyWithResult failed: %v", err)
	}
	if res.Provenance == nil || !res.Provenance.Attested {
		t.Fatalf("expected Provenance to be attested")
	}

	// Check FormatInspect includes Release Attestation
	inspectedOutput := res.FormatInspect()
	if !strings.Contains(inspectedOutput, "Release Attestation:") ||
		!strings.Contains(inspectedOutput, "Certified Release (gitlab-fleet-governor v1.0.0)") {
		t.Fatalf("expected release attestation in FormatInspect, got:\n%s", inspectedOutput)
	}
}
