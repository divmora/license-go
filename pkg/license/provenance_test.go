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

	// Evaluation at 2029-06-02 (after 3 years from 2026-06-01): Converts legally with server time attestation!
	evalTimeAfter := time.Date(2029, 6, 2, 0, 0, 0, 0, time.UTC)
	legitValAttested, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v1.0.0"),
		WithBSLPolicy(legitBSL),
		WithReleaseAttestation(attestationToken),
		WithServerTimeAttestation(evalTimeAfter, 1*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	resAfter, err := legitValAttested.VerifyWithResultAt("", evalTimeAfter)
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

func TestEvaluateProvenance_PlaceholderValues(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	params := ProvenanceParams{
		ExpectedProduct: "gitlab-fleet-governor",
		CurrentVersion:  "v1.0.0",
	}

	placeholders := []string{
		"",
		"   ",
		"none",
		"None",
		"NONE",
		`"none"`,
		"'none'",
		"dev",
		"development",
		"unattested",
		"null",
		"nil",
		"false",
		"disabled",
		"0",
		"unset",
		"n/a",
		"na",
		"undefined",
		"unknown",
		"placeholder",
		"test",
	}

	for _, ph := range placeholders {
		t.Run("placeholder: "+ph, func(t *testing.T) {
			if !IsPlaceholderAttestation(ph) {
				t.Fatalf("expected IsPlaceholderAttestation(%q) to be true", ph)
			}

			prov, err := EvaluateProvenance(ph, ring, params)
			if err != nil {
				t.Fatalf("EvaluateProvenance(%q) failed: %v", ph, err)
			}
			if prov == nil {
				t.Fatalf("expected non-nil ReleaseProvenance for %q", ph)
			}
			if prov.Attested {
				t.Fatalf("expected Attested == false for placeholder %q", ph)
			}
		})
	}

	// Non-placeholder invalid token should still return error
	_, err := EvaluateProvenance("some-invalid-token", ring, params)
	if err == nil {
		t.Fatal("expected error for non-placeholder invalid token, got nil")
	}
}

func TestValidator_PlaceholderAttestation_RequireAttestation(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	claims := Claims{
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Customer:  Customer{Name: "Acme Corp"},
	}
	signer, _ := NewSigner(priv)
	lic, _ := signer.Sign(claims)

	// 1. Placeholder with WithRequireReleaseAttestation(false): cleanly treated as unattested (no error)
	vUnattested, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithReleaseAttestation("none"),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	res, err := vUnattested.VerifyWithResult(lic)
	if err != nil {
		t.Fatalf("VerifyWithResult failed: %v", err)
	}
	if res.Provenance == nil || res.Provenance.Attested {
		t.Fatalf("expected Attested == false for 'none' placeholder")
	}

	// 2. Placeholder with WithRequireReleaseAttestation(true): fails with ErrReleaseAttestationMissing
	vRequired, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation("dev"),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	_, err = vRequired.Verify(lic)
	if !errors.Is(err, ErrReleaseAttestationMissing) {
		t.Fatalf("expected ErrReleaseAttestationMissing for 'dev' placeholder with RequireReleaseAttestation, got: %v", err)
	}
}

func TestEvaluateProvenance_BuildDateSkewTolerance(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	officialBuild := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	relClaims := ReleaseClaims{
		Product:   "otel-aws-log-processor",
		Version:   "v1.0.0",
		BuildDate: officialBuild,
	}
	token, err := SignRelease(relClaims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	t.Run("bi-directional drift: future build date beyond default 24h", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct:  "otel-aws-log-processor",
			CurrentVersion:   "v1.0.0",
			CurrentBuildDate: officialBuild.Add(48 * time.Hour), // 2 days in future
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "build date tampered") {
			t.Fatalf("expected build date tampering for future timestamp, got: %v", err)
		}
		if !errors.Is(err, ErrReleaseTampered) {
			t.Fatalf("expected ErrReleaseTampered, got: %v", err)
		}
	})

	t.Run("bi-directional drift: past build date beyond default 24h", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct:  "otel-aws-log-processor",
			CurrentVersion:   "v1.0.0",
			CurrentBuildDate: officialBuild.Add(-48 * time.Hour), // 2 days in past
		}
		_, err := EvaluateProvenance(token, ring, params)
		if err == nil || !strings.Contains(err.Error(), "build date tampered") {
			t.Fatalf("expected build date tampering for past timestamp, got: %v", err)
		}
		if !errors.Is(err, ErrReleaseTampered) {
			t.Fatalf("expected ErrReleaseTampered, got: %v", err)
		}
	})

	t.Run("within default tolerance (2 hours)", func(t *testing.T) {
		params := ProvenanceParams{
			ExpectedProduct:  "otel-aws-log-processor",
			CurrentVersion:   "v1.0.0",
			CurrentBuildDate: officialBuild.Add(2 * time.Hour),
		}
		prov, err := EvaluateProvenance(token, ring, params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prov.Tampered {
			t.Fatalf("expected not tampered, got: %s", prov.TamperReason)
		}
	})

	t.Run("custom MaxBuildDateSkew", func(t *testing.T) {
		paramsFail := ProvenanceParams{
			ExpectedProduct:  "otel-aws-log-processor",
			CurrentVersion:   "v1.0.0",
			CurrentBuildDate: officialBuild.Add(10 * time.Minute),
			MaxBuildDateSkew: 5 * time.Minute,
		}
		_, err := EvaluateProvenance(token, ring, paramsFail)
		if err == nil || !strings.Contains(err.Error(), "build date tampered") {
			t.Fatalf("expected build date tampering, got: %v", err)
		}

		paramsPass := ProvenanceParams{
			ExpectedProduct:  "otel-aws-log-processor",
			CurrentVersion:   "v1.0.0",
			CurrentBuildDate: officialBuild.Add(2 * time.Minute),
			MaxBuildDateSkew: 5 * time.Minute,
		}
		prov, err := EvaluateProvenance(token, ring, paramsPass)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prov.Tampered {
			t.Fatalf("expected not tampered")
		}
	})

	t.Run("strict build date enforcement", func(t *testing.T) {
		paramsStrictFail := ProvenanceParams{
			ExpectedProduct:        "otel-aws-log-processor",
			CurrentVersion:         "v1.0.0",
			CurrentBuildDate:       officialBuild.Add(5 * time.Minute),
			RequireStrictBuildDate: true,
		}
		_, err := EvaluateProvenance(token, ring, paramsStrictFail)
		if err == nil || !strings.Contains(err.Error(), "build date tampered") {
			t.Fatalf("expected build date tampering under strict mode, got: %v", err)
		}

		paramsStrictPass := ProvenanceParams{
			ExpectedProduct:        "otel-aws-log-processor",
			CurrentVersion:         "v1.0.0",
			CurrentBuildDate:       officialBuild.Add(30 * time.Second),
			RequireStrictBuildDate: true,
		}
		prov, err := EvaluateProvenance(token, ring, paramsStrictPass)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prov.Tampered {
			t.Fatalf("expected not tampered")
		}
	})

	t.Run("Validator options WithMaxBuildDateSkew and WithRequireStrictBuildDate", func(t *testing.T) {
		val, err := NewValidator(pub,
			WithProduct("otel-aws-log-processor"),
			WithCurrentVersion("v1.0.0"),
			WithBuildDate(officialBuild.Add(5*time.Minute)),
			WithReleaseAttestation(token),
			WithRequireStrictBuildDate(true),
		)
		if err != nil {
			t.Fatalf("NewValidator failed: %v", err)
		}
		_, err = val.EvaluateProvenance()
		if err == nil || !strings.Contains(err.Error(), "build date tampered") {
			t.Fatalf("expected build date tampering from Validator, got: %v", err)
		}

		valWithSkew, err := NewValidator(pub,
			WithProduct("otel-aws-log-processor"),
			WithCurrentVersion("v1.0.0"),
			WithBuildDate(officialBuild.Add(5*time.Minute)),
			WithReleaseAttestation(token),
			WithMaxBuildDateSkew(10*time.Minute),
		)
		if err != nil {
			t.Fatalf("NewValidator failed: %v", err)
		}
		prov, err := valWithSkew.EvaluateProvenance()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prov.Tampered {
			t.Fatalf("expected not tampered")
		}
	})
}

func TestEvaluateProvenance_VersionCheckFailClosed(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	claims := Claims{
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Customer:  Customer{Name: "Acme Corp"},
	}
	signer, _ := NewSigner(priv)
	lic, _ := signer.Sign(claims)

	relClaims := ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "v2.5.0",
		BuildDate: time.Now(),
	}
	token, err := SignRelease(relClaims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	// 1. RequireReleaseAttestation is true, but CurrentVersion is omitted -> FAIL CLOSED
	valOmittedVersion, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(token),
		// Note: WithCurrentVersion is omitted
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	_, err = valOmittedVersion.Verify(lic)
	if err == nil || !strings.Contains(err.Error(), "version verification required") {
		t.Fatalf("expected version verification required error, got: %v", err)
	}
	if !errors.Is(err, ErrReleaseTampered) {
		t.Fatalf("expected ErrReleaseTampered, got: %v", err)
	}

	// 2. CurrentVersion is provided and matches -> PASS
	valMatchedVersion, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(token),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	res, err := valMatchedVersion.VerifyWithResult(lic)
	if err != nil {
		t.Fatalf("VerifyWithResult failed: %v", err)
	}
	if !res.Provenance.Attested {
		t.Fatalf("expected attested provenance")
	}

	// 3. When RequireReleaseAttestation is false, omitted CurrentVersion does not fail closed
	paramsOptional := ProvenanceParams{
		ExpectedProduct:           "gitlab-fleet-governor",
		RequireReleaseAttestation: false,
		// CurrentVersion is empty
	}
	prov, err := EvaluateProvenance(token, ring, paramsOptional)
	if err != nil {
		t.Fatalf("EvaluateProvenance should succeed when RequireReleaseAttestation is false, got: %v", err)
	}
	if prov.Tampered {
		t.Fatalf("expected not tampered")
	}
}

func TestEvaluateProvenance_GitCommitFailClosed(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	claims := Claims{
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Customer:  Customer{Name: "Acme Corp"},
	}
	signer, _ := NewSigner(priv)
	lic, _ := signer.Sign(claims)

	relClaims := ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "v2.5.0",
		GitCommit: "deadbeefcafe12345678",
		BuildDate: time.Now(),
	}
	token, err := SignRelease(relClaims, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	// 1. RequireReleaseAttestation is true, GitCommit is attested, but running binary commit omitted -> FAIL CLOSED
	valOmittedCommit, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(token),
		// Note: WithCurrentGitCommit is omitted
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	_, err = valOmittedCommit.Verify(lic)
	if err == nil || !strings.Contains(err.Error(), "git commit verification required") {
		t.Fatalf("expected git commit verification required error, got: %v", err)
	}
	if !errors.Is(err, ErrReleaseTampered) {
		t.Fatalf("expected ErrReleaseTampered, got: %v", err)
	}

	// 2. Git commit provided and matches prefix -> PASS
	valMatchedCommit, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithCurrentGitCommit("deadbeef"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(token),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	res, err := valMatchedCommit.VerifyWithResult(lic)
	if err != nil {
		t.Fatalf("VerifyWithResult failed: %v", err)
	}
	if !res.Provenance.Attested {
		t.Fatalf("expected attested provenance")
	}

	// 3. Git commit provided but wrong -> FAIL
	valWrongCommit, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithCurrentGitCommit("11112222"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(token),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	_, err = valWrongCommit.Verify(lic)
	if err == nil || !strings.Contains(err.Error(), "git commit mismatch") {
		t.Fatalf("expected git commit mismatch error, got: %v", err)
	}

	// 4. When RequireReleaseAttestation is false, omitted CurrentCommit does not fail closed
	paramsOptional := ProvenanceParams{
		ExpectedProduct:           "gitlab-fleet-governor",
		CurrentVersion:            "v2.5.0",
		RequireReleaseAttestation: false,
	}
	prov, err := EvaluateProvenance(token, ring, paramsOptional)
	if err != nil {
		t.Fatalf("EvaluateProvenance should succeed when RequireReleaseAttestation is false, got: %v", err)
	}
	if prov.Tampered {
		t.Fatalf("expected not tampered")
	}
}

func TestEvaluateProvenance_BinaryDigestFailClosed(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	ring := NewKeyRing(pub)

	claims := Claims{
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Customer:  Customer{Name: "Acme Corp"},
	}
	signer, _ := NewSigner(priv)
	lic, _ := signer.Sign(claims)

	binaryBytes := []byte("legitimate binary content")
	digest := ComputeBytesDigest(binaryBytes)

	relClaimsWithDigest := ReleaseClaims{
		Product:      "gitlab-fleet-governor",
		Version:      "v2.5.0",
		BinaryDigest: digest,
		BuildDate:    time.Now(),
	}
	tokenWithDigest, err := SignRelease(relClaimsWithDigest, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	// 1. Attestation has digest, RequireReleaseAttestation is true, but binary bytes/path omitted -> FAIL CLOSED
	valOmittedDigest, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(tokenWithDigest),
		// Note: WithBinaryBytes / WithBinaryPath omitted
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	_, err = valOmittedDigest.Verify(lic)
	if err == nil || !strings.Contains(err.Error(), "binary digest verification required") {
		t.Fatalf("expected binary digest verification required error, got: %v", err)
	}
	if !errors.Is(err, ErrReleaseTampered) {
		t.Fatalf("expected ErrReleaseTampered, got: %v", err)
	}

	// 2. Attestation has digest, binary bytes provided and MATCH -> PASS
	valMatchedDigest, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithBinaryBytes(binaryBytes),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(tokenWithDigest),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	res, err := valMatchedDigest.VerifyWithResult(lic)
	if err != nil {
		t.Fatalf("VerifyWithResult failed: %v", err)
	}
	if !res.Provenance.DigestMatched {
		t.Fatalf("expected DigestMatched to be true")
	}

	// 3. Attestation has digest, binary bytes provided but TAMPERED -> FAIL with ErrReleaseDigestMismatch
	valTamperedDigest, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithCurrentVersion("v2.5.0"),
		WithBinaryBytes([]byte("tampered binary content")),
		WithRequireReleaseAttestation(true),
		WithReleaseAttestation(tokenWithDigest),
	)
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}
	_, err = valTamperedDigest.Verify(lic)
	if err == nil || !errors.Is(err, ErrReleaseDigestMismatch) {
		t.Fatalf("expected ErrReleaseDigestMismatch, got: %v", err)
	}

	// 4. Attestation has NO digest, but binary provided bytes, and RequireReleaseAttestation is true -> FAIL CLOSED
	relClaimsNoDigest := ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "v2.5.0",
		BuildDate: time.Now(),
	}
	tokenNoDigest, err := SignRelease(relClaimsNoDigest, priv)
	if err != nil {
		t.Fatalf("SignRelease failed: %v", err)
	}

	paramsMismatchedConfig := ProvenanceParams{
		ExpectedProduct:           "gitlab-fleet-governor",
		CurrentVersion:            "v2.5.0",
		BinaryBytes:               binaryBytes,
		RequireReleaseAttestation: true,
	}
	_, err = EvaluateProvenance(tokenNoDigest, ring, paramsMismatchedConfig)
	if err == nil || !strings.Contains(err.Error(), "binary digest verification required") {
		t.Fatalf("expected binary digest verification required when attestation lacks digest, got: %v", err)
	}
}

func TestReleaseClaims_NormalizedVersionAndArmored(t *testing.T) {
	rc := ReleaseClaims{Version: "v1.2.3"}
	if rc.NormalizedVersion() != "1.2.3" {
		t.Errorf("expected '1.2.3', got %q", rc.NormalizedVersion())
	}

	payload := []byte(`{"product":"test"}`)
	sig := make([]byte, 64)
	armored := EncodeReleaseArmored(payload, sig)
	if !strings.Contains(armored, "-----BEGIN DIVMORA RELEASE ATTESTATION-----") {
		t.Errorf("unexpected armored output: %s", armored)
	}
}

func TestReleaseClaims_Validate(t *testing.T) {
	now := time.Now().UTC()

	// Valid
	rcValid := ReleaseClaims{
		Product:   "gitlab-fleet-governor",
		Version:   "v1.0.0",
		BuildDate: now,
	}
	if err := rcValid.Validate(); err != nil {
		t.Fatalf("expected valid claims, got error: %v", err)
	}

	// Missing product
	rcNoProd := ReleaseClaims{Version: "v1.0.0", BuildDate: now}
	if err := rcNoProd.Validate(); err == nil {
		t.Error("expected error for missing product")
	}

	// Missing version
	rcNoVer := ReleaseClaims{Product: "my-app", BuildDate: now}
	if err := rcNoVer.Validate(); err == nil {
		t.Error("expected error for missing version")
	}

	// Missing build and release date
	rcNoDates := ReleaseClaims{Product: "my-app", Version: "v1.0.0"}
	if err := rcNoDates.Validate(); err == nil {
		t.Error("expected error for missing dates")
	}
}

func TestProvenance_ComputeDigests(t *testing.T) {
	content := []byte("binary executable data")
	expectedDigest := ComputeBytesDigest(content)

	// ComputeReaderDigest
	readerDigest, err := ComputeReaderDigest(strings.NewReader(string(content)))
	if err != nil || readerDigest != expectedDigest {
		t.Errorf("ComputeReaderDigest error=%v, digest=%s (want %s)", err, readerDigest, expectedDigest)
	}

	// ComputeFileDigest
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "binary.bin")
	if err := os.WriteFile(binPath, content, 0755); err != nil {
		t.Fatal(err)
	}

	fileDigest, err := ComputeFileDigest(binPath)
	if err != nil || fileDigest != expectedDigest {
		t.Errorf("ComputeFileDigest error=%v, digest=%s (want %s)", err, fileDigest, expectedDigest)
	}

	// Non-existent file
	_, err = ComputeFileDigest(filepath.Join(tmpDir, "nonexistent"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestReleaseClaims_MatchingAndInspectMethods(t *testing.T) {
	rel := &ReleaseClaims{
		Product:      "gitlab-fleet-governor",
		Version:      "v1.2.3",
		GitCommit:    "897f058123456789abcdef",
		BinaryDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	// 1. MatchesVersion
	if !rel.MatchesVersion("") {
		t.Error("expected true for empty running version")
	}
	if !rel.MatchesVersion("1.2.3") {
		t.Error("expected true for normalized version match")
	}
	if rel.MatchesVersion("1.2.4") {
		t.Error("expected false for different version")
	}

	// 2. MatchesCommit
	if !rel.MatchesCommit("") {
		t.Error("expected true for empty running commit")
	}
	if !rel.MatchesCommit("897f058123456789abcdef") {
		t.Error("expected true for exact commit match")
	}
	if !rel.MatchesCommit("897f058") {
		t.Error("expected true for short commit prefix match")
	}
	if rel.MatchesCommit("deadbeef") {
		t.Error("expected false for mismatch commit")
	}

	// Empty commit on claims
	relNoCommit := &ReleaseClaims{}
	if !relNoCommit.MatchesCommit("any-commit") {
		t.Error("expected true when claims has no commit")
	}

	// 3. MatchesDigest
	if !rel.MatchesDigest("") {
		t.Error("expected true for empty digest")
	}
	if !rel.MatchesDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Error("expected true for identical digest")
	}
	if !rel.MatchesDigest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Error("expected true for digest without sha256: prefix")
	}
	if rel.MatchesDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("expected false for mismatch digest")
	}

	// 4. InspectRelease error paths
	if _, err := InspectRelease("invalid-release-token"); err == nil {
		t.Error("expected error for invalid release token format")
	}
}
