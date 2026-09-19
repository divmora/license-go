package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateCRLTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keypair: %v", err)
	}
	return pub, priv
}

func TestCRL_SignAndVerify_CompactAndArmored(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	if _, err := ring.AddKey(pub, WithCustomKeyID("crl-signer-2026")); err != nil {
		t.Fatalf("ring.AddKey failed: %v", err)
	}

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nextUpdate := now.Add(30 * 24 * time.Hour)

	claims := RevocationListClaims{
		ID:         "crl-2026-001",
		Issuer:     "divmora.com/crl",
		Product:    "gitlab-fleet-governor",
		KeyID:      "crl-signer-2026",
		IssuedAt:   now,
		NextUpdate: nextUpdate,
		Entries: []RevocationEntry{
			{
				ID:        "550e8400-e29b-41d4-a716-446655440000",
				RevokedAt: now.Add(-2 * 24 * time.Hour),
				Reason:    "compromised credentials",
			},
			{
				ID:        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
				RevokedAt: now.Add(-1 * 24 * time.Hour),
				Reason:    "refunded contract",
			},
		},
		Metadata: map[string]string{
			"security_contact": "secops@divmora.com",
			"tier":             "enterprise",
		},
	}

	// 1. Sign compact token
	compactToken, err := SignCRL(claims, priv, WithCRLSignerKeyID("crl-signer-2026"))
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}
	if !strings.HasPrefix(compactToken, ProtocolPrefixCRL+".") {
		t.Fatalf("expected prefix %s, got %s", ProtocolPrefixCRL, compactToken)
	}

	// Verify compact token
	verifiedClaims, keyEntry, err := VerifyCRL(compactToken, ring)
	if err != nil {
		t.Fatalf("VerifyCRL failed: %v", err)
	}
	if verifiedClaims.ID != "crl-2026-001" || verifiedClaims.Count() != 2 {
		t.Fatalf("unexpected verified claims: %+v", verifiedClaims)
	}
	if keyEntry.ID != "crl-signer-2026" {
		t.Fatalf("expected key ID crl-signer-2026, got %s", keyEntry.ID)
	}

	// Check IsRevoked
	entry, revoked := verifiedClaims.IsRevoked("550e8400-e29b-41d4-a716-446655440000")
	if !revoked || entry.Reason != "compromised credentials" {
		t.Fatalf("expected 550e8400... to be revoked with reason 'compromised credentials'")
	}
	// Case-insensitive check
	entryUpper, revokedUpper := verifiedClaims.IsRevoked("550E8400-E29B-41D4-A716-446655440000")
	if !revokedUpper || entryUpper == nil {
		t.Fatalf("expected case-insensitive match for revocation")
	}
	// Unrevoked ID check
	_, notRevoked := verifiedClaims.IsRevoked("unknown-uuid")
	if notRevoked {
		t.Fatalf("expected unknown-uuid to NOT be revoked")
	}

	// 2. Sign armored PEM block
	armoredPEM, err := SignCRLArmored(claims, priv, WithCRLSignerKeyID("crl-signer-2026"))
	if err != nil {
		t.Fatalf("SignCRLArmored failed: %v", err)
	}
	if !strings.Contains(armoredPEM, "-----BEGIN "+PEMTypeRevocationList+"-----") {
		t.Fatalf("expected armored PEM block, got:\n%s", armoredPEM)
	}

	// Verify armored PEM block
	verifiedArmored, _, err := VerifyCRL(armoredPEM, ring)
	if err != nil {
		t.Fatalf("VerifyCRL with armored PEM failed: %v", err)
	}
	if verifiedArmored.ID != claims.ID {
		t.Fatalf("expected ID %s, got %s", claims.ID, verifiedArmored.ID)
	}

	// 3. Inspect without verification
	inspected, err := InspectCRL(armoredPEM)
	if err != nil {
		t.Fatalf("InspectCRL failed: %v", err)
	}
	if inspected.Issuer != "divmora.com/crl" {
		t.Fatalf("expected issuer divmora.com/crl, got %s", inspected.Issuer)
	}

	// Inspect from file
	tmpDir := t.TempDir()
	crlFile := filepath.Join(tmpDir, "crl.divcrl")
	if err := os.WriteFile(crlFile, []byte(armoredPEM), 0644); err != nil {
		t.Fatalf("failed to write crl file: %v", err)
	}
	fromFile, err := InspectCRLFromFile(crlFile)
	if err != nil {
		t.Fatalf("InspectCRLFromFile failed: %v", err)
	}
	if fromFile.Count() != 2 {
		t.Fatalf("expected 2 revoked entries, got %d", fromFile.Count())
	}
}

func TestCRL_Expiration(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	claims := RevocationListClaims{
		ID:         "crl-exp-test",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
	}

	if claims.IsExpiredAt(now.Add(12 * time.Hour)) {
		t.Fatalf("CRL should not be expired before NextUpdate")
	}
	if !claims.IsExpiredAt(now.Add(25 * time.Hour)) {
		t.Fatalf("CRL should be expired after NextUpdate")
	}

	// Perpetual CRL
	claimsPerpetual := RevocationListClaims{
		ID:       "crl-perpetual",
		IssuedAt: now,
	}
	if claimsPerpetual.IsExpiredAt(now.Add(1000 * 24 * time.Hour)) {
		t.Fatalf("Perpetual CRL should never expire")
	}
}

func TestCRL_TamperingAndSecurity(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	claims := RevocationListClaims{
		ID:       "crl-sec-test",
		IssuedAt: time.Now().UTC(),
		Entries: []RevocationEntry{
			{ID: "lic-1", Reason: "compromised"},
		},
	}

	token, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	// 1. Corrupted signature segment
	parts := strings.Split(token, ".")
	corrupted := parts[0] + "." + parts[1] + ".invalid-signature"
	if _, _, err := VerifyCRL(corrupted, ring); err == nil {
		t.Fatalf("expected error for corrupted signature, got nil")
	}

	// 2. Untrusted signing key
	_, otherPriv := generateCRLTestKeyPair(t)
	untrustedToken, _ := SignCRL(claims, otherPriv)
	if _, _, err := VerifyCRL(untrustedToken, ring); !errors.Is(err, ErrInvalidCRL) {
		t.Fatalf("expected ErrInvalidCRL for untrusted key, got %v", err)
	}

	// 3. Empty token
	if _, _, err := VerifyCRL("", ring); !errors.Is(err, ErrInvalidCRL) {
		t.Fatalf("expected ErrInvalidCRL for empty token, got %v", err)
	}

	// 4. Missing public key
	if _, _, err := VerifyCRL(token, NewKeyRing(nil)); !errors.Is(err, ErrMissingPublicKey) {
		t.Fatalf("expected ErrMissingPublicKey, got %v", err)
	}
}

func TestCRL_ValidatorIntegration(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	// Issue two valid licenses
	now := time.Now().UTC()
	goodClaims := Claims{
		ID:       "lic-good-12345",
		Customer: Customer{Name: "Acme Corp"},
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		IssuedAt: now,
	}
	revokedClaims := Claims{
		ID:       "lic-revoked-99999",
		Customer: Customer{Name: "Evil Corp"},
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		IssuedAt: now,
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	goodToken, err := signer.Sign(goodClaims)
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}
	revokedToken, err := signer.Sign(revokedClaims)
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	// Mint CRL revoking lic-revoked-99999
	crlClaims := RevocationListClaims{
		ID:         "crl-test-val",
		Issuer:     "divmora.com/crl",
		IssuedAt:   now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
		Entries: []RevocationEntry{
			{
				ID:        "lic-revoked-99999",
				RevokedAt: now.Add(-1 * time.Hour),
				Reason:    "breach of agreement",
			},
		},
	}
	crlArmored, err := SignCRLArmored(crlClaims, priv)
	if err != nil {
		t.Fatalf("SignCRLArmored failed: %v", err)
	}

	// 1. Validator without CRL: both licenses succeed
	vWithoutCRL, err := NewValidatorWithKeyRing(ring, WithProduct("gitlab-fleet-governor"))
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}
	if _, err := vWithoutCRL.Verify(goodToken); err != nil {
		t.Fatalf("expected good license to verify, got %v", err)
	}
	if _, err := vWithoutCRL.Verify(revokedToken); err != nil {
		t.Fatalf("expected revoked license to verify without CRL, got %v", err)
	}

	// 2. Validator with CRL: good license passes, revoked license fails
	vWithCRL, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("gitlab-fleet-governor"),
		WithRevocationList(crlArmored),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing with CRL failed: %v", err)
	}

	// Good license passes
	resGood, err := vWithCRL.VerifyWithResult(goodToken)
	if err != nil {
		t.Fatalf("expected good license to pass with CRL, got %v", err)
	}
	if resGood.Revoked {
		t.Fatalf("good license should not be flagged as revoked")
	}

	// Revoked license fails
	_, errRevoked := vWithCRL.Verify(revokedToken)
	if errRevoked == nil {
		t.Fatalf("expected revoked license to fail validation, got nil")
	}
	if !errors.Is(errRevoked, ErrLicenseRevoked) {
		t.Fatalf("expected errors.Is(err, ErrLicenseRevoked), got %v", errRevoked)
	}

	var revErr *LicenseRevokedError
	if !errors.As(errRevoked, &revErr) {
		t.Fatalf("expected error to be *LicenseRevokedError, got %T", errRevoked)
	}
	if revErr.LicenseID != "lic-revoked-99999" || revErr.Reason != "breach of agreement" {
		t.Fatalf("unexpected revErr details: %+v", revErr)
	}
	if revErr.CRLID != "crl-test-val" {
		t.Fatalf("expected CRLID crl-test-val, got %s", revErr.CRLID)
	}

	// 3. Test WithRevocationListFile
	tmpDir := t.TempDir()
	crlFilePath := filepath.Join(tmpDir, "active.crl")
	if err := os.WriteFile(crlFilePath, []byte(crlArmored), 0644); err != nil {
		t.Fatalf("failed to write crl file: %v", err)
	}

	vWithFile, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("gitlab-fleet-governor"),
		WithRevocationListFile(crlFilePath),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing with CRL file failed: %v", err)
	}
	if _, err := vWithFile.Verify(revokedToken); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked with CRL file, got %v", err)
	}
}

func TestCRL_StrictExpiry(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	expiredCRLClaims := RevocationListClaims{
		ID:         "crl-expired",
		IssuedAt:   now.Add(-48 * time.Hour),
		NextUpdate: now.Add(-24 * time.Hour), // Expired yesterday
		Entries: []RevocationEntry{
			{ID: "lic-123", Reason: "testing"},
		},
	}
	crlToken, err := SignCRL(expiredCRLClaims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	licClaims := Claims{
		ID:       "lic-unrevoked",
		Customer: Customer{Name: "Acme"},
		Product:  "app",
		Plan:     "pro",
		IssuedAt: now,
	}
	strictSigner, _ := NewSigner(priv)
	licToken, _ := strictSigner.Sign(licClaims)

	// Lenient expiry (default): does not fail unrevoked license on expired CRL
	vLenient, _ := NewValidatorWithKeyRing(ring, WithProduct("app"), WithRevocationList(crlToken))
	if _, err := vLenient.Verify(licToken); err != nil {
		t.Fatalf("lenient validator should pass unrevoked license, got %v", err)
	}

	// Strict expiry: fails with ErrCRLExpired
	vStrict, _ := NewValidatorWithKeyRing(
		ring,
		WithProduct("app"),
		WithRevocationList(crlToken),
		WithCRLStrictExpiry(true),
	)
	if _, err := vStrict.Verify(licToken); !errors.Is(err, ErrCRLExpired) {
		t.Fatalf("expected ErrCRLExpired in strict mode, got %v", err)
	}
}

func TestCRL_FormatInspect(t *testing.T) {
	claims := RevocationListClaims{
		ID:         "crl-inspect-view",
		Issuer:     "divmora.com/crl",
		Product:    "gitlab-fleet-governor",
		KeyID:      "key-2026",
		IssuedAt:   time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		Entries: []RevocationEntry{
			{ID: "uuid-1", RevokedAt: time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC), Reason: "stolen key"},
		},
		Metadata: map[string]string{
			"env": "production",
		},
	}

	inspectOutput := claims.FormatInspect()
	if !strings.Contains(inspectOutput, "DIVMORA CERTIFICATE REVOCATION LIST (CRL)") {
		t.Fatalf("expected header in inspect output, got:\n%s", inspectOutput)
	}
	if !strings.Contains(inspectOutput, "crl-inspect-view") || !strings.Contains(inspectOutput, "stolen key") {
		t.Fatalf("expected CRL ID and reason in inspect output, got:\n%s", inspectOutput)
	}
}

func TestValidator_RequireRevocationList(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	licClaims := Claims{
		ID:       "lic-require-crl-1",
		Customer: Customer{Name: "Acme Corp"},
		Product:  "app",
		Plan:     "enterprise",
		IssuedAt: now,
	}
	signer, _ := NewSigner(priv)
	licToken, err := signer.Sign(licClaims)
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	// 1. WithRequireRevocationList(true) when NO CRL is configured -> fails with ErrCRLMissing
	vMissing, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("app"),
		WithRequireRevocationList(true),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}
	if _, err := vMissing.Verify(licToken); !errors.Is(err, ErrCRLMissing) {
		t.Fatalf("expected ErrCRLMissing, got: %v", err)
	}

	// 2. With CRL provided -> succeeds
	crlClaims := RevocationListClaims{
		ID:       "crl-valid-1",
		IssuedAt: now,
		Entries:  []RevocationEntry{},
	}
	crlToken, _ := SignCRL(crlClaims, priv)

	vPresent, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("app"),
		WithRevocationList(crlToken),
		WithRequireRevocationList(true),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}
	if _, err := vPresent.Verify(licToken); err != nil {
		t.Fatalf("expected verification success when required CRL is present, got: %v", err)
	}
}

func TestValidator_AutoResolveRevocationList(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	revokedID := "lic-auto-resolve-revoked"
	crlClaims := RevocationListClaims{
		ID:       "crl-auto-resolved",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: revokedID, RevokedAt: now, Reason: "compromised"},
		},
	}
	crlToken, _ := SignCRL(crlClaims, priv)

	// Set environment variable DIVMORA_CRL
	t.Setenv(EnvCRL, crlToken)

	signer, _ := NewSigner(priv)
	licToken, err := signer.Sign(Claims{
		ID:       revokedID,
		Customer: Customer{Name: "Acme Corp"},
		Product:  "app",
		Plan:     "enterprise",
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	vAuto, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("app"),
		WithAutoResolvedRevocationList(true),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}

	_, err = vAuto.Verify(licToken)
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked via auto-resolved CRL, got: %v", err)
	}
}

func TestValidator_WithCRLURL(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	revokedID := "lic-dynamic-crl-revoked"
	validID := "lic-dynamic-crl-valid"

	crlClaims := RevocationListClaims{
		ID:       "crl-endpoint-test",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: revokedID, RevokedAt: now, Reason: "fraudulent chargeback"},
		},
	}
	crlToken, _ := SignCRL(crlClaims, priv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"crl-endpoint-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(crlToken))
	}))
	defer ts.Close()

	cacheFile := filepath.Join(t.TempDir(), "dynamic-crl.cache")

	v, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("app"),
		WithCRLURL(ts.URL, WithCRLSyncCacheFile(cacheFile)),
		WithRequireRevocationList(true),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}

	signer, _ := NewSigner(priv)

	// 1. Verify revoked license is rejected
	revokedToken, err := signer.Sign(Claims{
		ID:       revokedID,
		Customer: Customer{Name: "Acme Corp"},
		Product:  "app",
		Plan:     "enterprise",
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}
	if _, err := v.Verify(revokedToken); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked for revoked token, got: %v", err)
	}

	// 2. Verify valid license passes
	validToken, err := signer.Sign(Claims{
		ID:       validID,
		Customer: Customer{Name: "Acme Corp"},
		Product:  "app",
		Plan:     "enterprise",
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}
	if _, err := v.Verify(validToken); err != nil {
		t.Fatalf("expected valid token to pass, got: %v", err)
	}
}

func TestValidator_ClaimsEmbeddedCRLURL(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	revokedID := "lic-claims-crl-revoked"
	validID := "lic-claims-crl-valid"

	crlClaims := RevocationListClaims{
		ID:       "crl-claims-test",
		IssuedAt: now,
		Entries: []RevocationEntry{
			{ID: revokedID, RevokedAt: now, Reason: "license terms breached"},
		},
	}
	crlToken, err := SignCRL(crlClaims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"crl-claims-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(crlToken))
	}))
	defer ts.Close()

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// 1. Issue a license embedding the CRLURL directly in its claims
	revokedToken, err := signer.Sign(Claims{
		ID:       revokedID,
		Customer: Customer{Name: "Acme Corp"},
		Product:  "app",
		Plan:     "enterprise",
		IssuedAt: now,
		CRLURL:   ts.URL,
	})
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	// 2. Validate with auto-resolve enabled: should automatically use claims.CRLURL (Tier 3)
	v, err := NewValidatorWithKeyRing(
		ring,
		WithProduct("app"),
		WithAutoResolvedRevocationList(true),
	)
	if err != nil {
		t.Fatalf("NewValidatorWithKeyRing failed: %v", err)
	}

	_, err = v.Verify(revokedToken)
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("expected ErrLicenseRevoked via claims.CRLURL, got: %v", err)
	}

	// 3. Issue valid license with CRLURL
	validToken, err := signer.Sign(Claims{
		ID:       validID,
		Customer: Customer{Name: "Acme Corp"},
		Product:  "app",
		Plan:     "enterprise",
		IssuedAt: now,
		CRLURL:   ts.URL,
	})
	if err != nil {
		t.Fatalf("signer.Sign failed: %v", err)
	}

	claims, err := v.Verify(validToken)
	if err != nil {
		t.Fatalf("expected valid token to pass, got: %v", err)
	}
	if claims.GetCRLURL() != ts.URL {
		t.Fatalf("expected GetCRLURL() == %q, got: %q", ts.URL, claims.GetCRLURL())
	}

	// 4. Verify FormatInspect includes CRL Distribution URL
	inspectOutput := claims.FormatInspect()
	if !strings.Contains(inspectOutput, "CRL Distribution URL:") || !strings.Contains(inspectOutput, ts.URL) {
		t.Fatalf("expected FormatInspect to include CRL Distribution URL, got:\n%s", inspectOutput)
	}

	// 5. Test Metadata["crl_url"] fallback
	metaClaims := &Claims{
		Metadata: map[string]string{"crl_url": "https://meta.example.com/crl"},
	}
	if metaClaims.GetCRLURL() != "https://meta.example.com/crl" {
		t.Fatalf("expected GetCRLURL to fallback to metadata, got: %s", metaClaims.GetCRLURL())
	}
}
