package license

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLicense_ExplicitFile(t *testing.T) {
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "license.key")
	expectedContent := "DIV1.explicit-file-content.signature"

	if err := os.WriteFile(licFile, []byte(expectedContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolved, err := ResolveLicense(licFile)
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}

	if resolved.Content != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, resolved.Content)
	}
	if resolved.FilePath != licFile {
		t.Errorf("expected filePath %q, got %q", licFile, resolved.FilePath)
	}
	if resolved.Source != "explicit_file" {
		t.Errorf("expected source explicit_file, got %q", resolved.Source)
	}
}

func TestResolveLicense_ExplicitTokenString(t *testing.T) {
	compact := "DIV1.inline-token-payload.signature"
	resolved, err := ResolveLicense(compact)
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	if resolved.Content != compact {
		t.Errorf("expected %q, got %q", compact, resolved.Content)
	}
	if resolved.FilePath != "" {
		t.Errorf("expected empty filePath for inline token, got %q", resolved.FilePath)
	}
	if resolved.Source != "explicit_token" {
		t.Errorf("expected source explicit_token, got %q", resolved.Source)
	}

	armored := "-----BEGIN DIVMORA LICENSE KEY-----\nDIV1.payload.sig\n-----END DIVMORA LICENSE KEY-----"
	resolvedArmored, err := ResolveLicense(armored)
	if err != nil {
		t.Fatalf("ResolveLicense failed on armored: %v", err)
	}
	if resolvedArmored.Content != armored {
		t.Errorf("expected armored content, got %q", resolvedArmored.Content)
	}
	if resolvedArmored.Source != "explicit_token" {
		t.Errorf("expected source explicit_token, got %q", resolvedArmored.Source)
	}
}

func TestResolveLicense_ExplicitMissingFile(t *testing.T) {
	_, err := ResolveLicense("/path/does/not/exist/license.key")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist error, got %v", err)
	}
}

func TestResolveLicense_EnvLicenseKey(t *testing.T) {
	expectedToken := "DIV1.env-token.sig"
	t.Setenv(EnvLicenseKey, expectedToken)
	t.Setenv(EnvLicenseFile, "")

	resolved, err := ResolveLicense()
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	if resolved.Content != expectedToken {
		t.Errorf("expected content %q, got %q", expectedToken, resolved.Content)
	}
	if resolved.Source != "env:"+EnvLicenseKey {
		t.Errorf("expected source env:%s, got %q", EnvLicenseKey, resolved.Source)
	}

	// Test ResolveToken helper
	token, err := ResolveToken()
	if err != nil || token != expectedToken {
		t.Errorf("ResolveToken() = (%q, %v), want (%q, nil)", token, err, expectedToken)
	}
}

func TestResolveLicense_EnvLicenseFile(t *testing.T) {
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "env-license.key")
	expectedContent := "DIV1.from-env-file.sig"

	if err := os.WriteFile(licFile, []byte(expectedContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicenseFile, licFile)

	resolved, err := ResolveLicense()
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	if resolved.Content != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, resolved.Content)
	}
	if resolved.FilePath != licFile {
		t.Errorf("expected filePath %q, got %q", licFile, resolved.FilePath)
	}
	if resolved.Source != "env:"+EnvLicenseFile {
		t.Errorf("expected source env:%s, got %q", EnvLicenseFile, resolved.Source)
	}
}

func TestResolveLicense_NotFound(t *testing.T) {
	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicenseFile, "")

	// On non-standard path without default /etc/divmora/license.key
	// (or if /etc/divmora/license.key does not exist)
	if _, err := os.Stat(DefaultLicensePath); os.IsNotExist(err) {
		_, err := ResolveLicense()
		if !errors.Is(err, ErrLicenseNotFound) {
			t.Fatalf("expected ErrLicenseNotFound, got %v", err)
		}
	}
}

func TestResolveLicense_MultiArgumentOrder(t *testing.T) {
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "company.key")
	fileContent := "DIV1.file-token.signature"
	if err := os.WriteFile(licFile, []byte(fileContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	inlineToken := "DIV1.inline-token.signature"

	// 1. ResolveToken("", licFile) -> must inspect second argument and return file content
	token, err := ResolveToken("", licFile)
	if err != nil {
		t.Fatalf("ResolveToken('', licFile) failed: %v", err)
	}
	if token != fileContent {
		t.Errorf("expected fileContent %q, got %q", fileContent, token)
	}

	// 2. ResolveToken(inlineToken, licFile) -> must prefer first non-empty argument
	tokenFirst, err := ResolveToken(inlineToken, licFile)
	if err != nil {
		t.Fatalf("ResolveToken(inlineToken, licFile) failed: %v", err)
	}
	if tokenFirst != inlineToken {
		t.Errorf("expected inlineToken %q, got %q", inlineToken, tokenFirst)
	}

	// 3. ResolveToken("", "") -> falls back to env
	t.Setenv(EnvLicenseKey, inlineToken)
	tokenEnv, err := ResolveToken("", "")
	if err != nil {
		t.Fatalf("ResolveToken('', '') fallback failed: %v", err)
	}
	if tokenEnv != inlineToken {
		t.Errorf("expected env inlineToken %q, got %q", inlineToken, tokenEnv)
	}

	// 4. ResolveToken("", "/nonexistent/path.key") -> must fail with os.ErrNotExist
	_, err = ResolveToken("", "/nonexistent/path.key")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestResolveKeyRing_ProgrammaticOverride(t *testing.T) {
	pub1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pub2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// 1. SetVerificationPublicKey override
	SetVerificationPublicKey(pub1)
	resolved, err := ResolveKeyRingWithSource()
	if err != nil {
		t.Fatalf("ResolveKeyRingWithSource failed: %v", err)
	}
	if resolved.Source != "programmatic_override" {
		t.Errorf("expected source programmatic_override, got %q", resolved.Source)
	}
	if string(resolved.Primary()) != string(pub1) {
		t.Errorf("expected primary key to match pub1")
	}

	// 2. ResolvePublicKey helper
	resolvedPub, err := ResolvePublicKey()
	if err != nil {
		t.Fatalf("ResolvePublicKey failed: %v", err)
	}
	if string(resolvedPub) != string(pub1) {
		t.Errorf("expected ResolvePublicKey to return pub1")
	}

	// 3. ResetVerificationPublicKey
	ResetVerificationPublicKey()

	// 4. SetVerificationKeyRing override with multi-key ring
	ringOverride := NewKeyRing(pub2, pub1)
	SetVerificationKeyRing(ringOverride)
	resolvedRing, err := ResolveKeyRing()
	if err != nil {
		t.Fatalf("ResolveKeyRing failed: %v", err)
	}
	if resolvedRing.Count() != 2 {
		t.Errorf("expected 2 keys in resolved ring, got %d", resolvedRing.Count())
	}
	if string(resolvedRing.Primary().PublicKey) != string(pub2) {
		t.Errorf("expected primary key to be pub2")
	}

	// 5. ResetVerificationKeyRing
	ResetVerificationKeyRing()
}

func TestResolveKeyRing_EnvPublicKeysPEM(t *testing.T) {
	ResetVerificationKeyRing()
	pub1, _, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()

	bundlePEM, err := EncodePublicKeysToPEM([]ed25519.PublicKey{pub1, pub2})
	if err != nil {
		t.Fatalf("EncodePublicKeysToPEM failed: %v", err)
	}

	// 1. Test inline PEM string in DIVMORA_PUBLIC_KEYS_PEM
	t.Setenv(EnvPublicKeysPEM, string(bundlePEM))
	t.Setenv(EnvPublicKey, "")
	t.Setenv(EnvPublicKeyFile, "")

	resolved, err := ResolveKeyRingWithSource()
	if err != nil {
		t.Fatalf("ResolveKeyRingWithSource failed: %v", err)
	}
	if resolved.Source != "env:"+EnvPublicKeysPEM {
		t.Errorf("expected source env:%s, got %q", EnvPublicKeysPEM, resolved.Source)
	}
	if resolved.KeyRing.Count() != 2 {
		t.Errorf("expected 2 keys in KeyRing, got %d", resolved.KeyRing.Count())
	}
	if string(resolved.Primary()) != string(pub1) {
		t.Errorf("expected primary key to be pub1")
	}

	// 2. Test file path in DIVMORA_PUBLIC_KEYS_PEM
	tempDir := t.TempDir()
	bundleFile := filepath.Join(tempDir, "trusted_keys.pem")
	if err := os.WriteFile(bundleFile, bundlePEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	t.Setenv(EnvPublicKeysPEM, bundleFile)
	resolvedFile, err := ResolveKeyRingWithSource()
	if err != nil {
		t.Fatalf("ResolveKeyRingWithSource from file path failed: %v", err)
	}
	if resolvedFile.FilePath != bundleFile {
		t.Errorf("expected filePath %q, got %q", bundleFile, resolvedFile.FilePath)
	}
	if resolvedFile.KeyRing.Count() != 2 {
		t.Errorf("expected 2 keys in KeyRing, got %d", resolvedFile.KeyRing.Count())
	}

	// 3. Invalid PEM returns error
	t.Setenv(EnvPublicKeysPEM, "not-a-valid-pem")
	_, err = ResolveKeyRing()
	if err == nil {
		t.Fatal("expected error for invalid PEM in DIVMORA_PUBLIC_KEYS_PEM, got nil")
	}
}

func TestResolveKeyRing_EnvPublicKey(t *testing.T) {
	ResetVerificationKeyRing()
	pub, _, _ := GenerateKeyPair()

	// 1. Raw 32-byte Base64 in DIVMORA_PUBLIC_KEY
	b64Raw := EncodePublicKeyToBase64(pub)
	t.Setenv(EnvPublicKeysPEM, "")
	t.Setenv(EnvPublicKey, b64Raw)
	t.Setenv(EnvPublicKeyFile, "")

	resolved, err := ResolveKeyRingWithSource()
	if err != nil {
		t.Fatalf("ResolveKeyRingWithSource with base64 failed: %v", err)
	}
	if resolved.Source != "env:"+EnvPublicKey {
		t.Errorf("expected source env:%s, got %q", EnvPublicKey, resolved.Source)
	}
	if string(resolved.Primary()) != string(pub) {
		t.Errorf("expected primary key to match pub")
	}

	// 2. Single key PEM in DIVMORA_PUBLIC_KEY
	pemData, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("EncodePublicKeyToPEM failed: %v", err)
	}
	t.Setenv(EnvPublicKey, string(pemData))
	resolvedPEM, err := ResolveKeyRing()
	if err != nil {
		t.Fatalf("ResolveKeyRing with PEM string failed: %v", err)
	}
	if string(resolvedPEM.Primary().PublicKey) != string(pub) {
		t.Errorf("expected primary key to match pub")
	}

	// 3. File path in DIVMORA_PUBLIC_KEY
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte(b64Raw), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	t.Setenv(EnvPublicKey, keyFile)
	resolvedKeyFile, err := ResolveKeyRingWithSource()
	if err != nil {
		t.Fatalf("ResolveKeyRingWithSource with file path in DIVMORA_PUBLIC_KEY failed: %v", err)
	}
	if resolvedKeyFile.FilePath != keyFile {
		t.Errorf("expected filePath %q, got %q", keyFile, resolvedKeyFile.FilePath)
	}
	if string(resolvedKeyFile.Primary()) != string(pub) {
		t.Errorf("expected primary key to match pub")
	}
}

func TestResolveKeyRing_EnvPublicKeyFile(t *testing.T) {
	ResetVerificationKeyRing()
	pub, _, _ := GenerateKeyPair()
	pemData, _ := EncodePublicKeyToPEM(pub)

	tempDir := t.TempDir()
	pubPath := filepath.Join(tempDir, "server_public.pem")
	if err := os.WriteFile(pubPath, pemData, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	t.Setenv(EnvPublicKeysPEM, "")
	t.Setenv(EnvPublicKey, "")
	t.Setenv(EnvPublicKeyFile, pubPath)

	resolved, err := ResolveKeyRingWithSource()
	if err != nil {
		t.Fatalf("ResolveKeyRingWithSource failed: %v", err)
	}
	if resolved.Source != "env:"+EnvPublicKeyFile {
		t.Errorf("expected source env:%s, got %q", EnvPublicKeyFile, resolved.Source)
	}
	if resolved.FilePath != pubPath {
		t.Errorf("expected filePath %q, got %q", pubPath, resolved.FilePath)
	}
	if string(resolved.Primary()) != string(pub) {
		t.Errorf("expected primary key to match pub")
	}

	// Missing file returns error
	t.Setenv(EnvPublicKeyFile, "/nonexistent/public.pem")
	_, err = ResolveKeyRing()
	if err == nil {
		t.Fatal("expected error for non-existent DIVMORA_PUBLIC_KEY_FILE")
	}
}

func TestResolveKeyRing_FallbackKeys(t *testing.T) {
	ResetVerificationKeyRing()
	t.Setenv(EnvPublicKeysPEM, "")
	t.Setenv(EnvPublicKey, "")
	t.Setenv(EnvPublicKeyFile, "")

	pub1, _, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()

	b64_1 := EncodePublicKeyToBase64(pub1)
	b64_2 := EncodePublicKeyToBase64(pub2)

	// 1. Single base64 fallback key
	ring, err := ResolveKeyRing(b64_1)
	if err != nil {
		t.Fatalf("ResolveKeyRing with fallback base64 failed: %v", err)
	}
	if string(ring.Primary().PublicKey) != string(pub1) {
		t.Errorf("expected primary key to match pub1")
	}

	// 2. Multiple fallback keys: first is active, second is retiring
	ringMulti, err := ResolveKeyRing(b64_1, b64_2)
	if err != nil {
		t.Fatalf("ResolveKeyRing with multiple fallbacks failed: %v", err)
	}
	if ringMulti.Count() != 2 {
		t.Errorf("expected 2 keys in KeyRing, got %d", ringMulti.Count())
	}
	keys := ringMulti.Keys()
	if keys[0].Status != KeyStatusActive {
		t.Errorf("expected first key status ACTIVE, got %s", keys[0].Status)
	}
	if keys[1].Status != KeyStatusRetiring {
		t.Errorf("expected second key status RETIRING, got %s", keys[1].Status)
	}

	// 3. Fallback PEM string
	pemData, _ := EncodePublicKeyToPEM(pub1)
	ringPEM, err := ResolveKeyRing(string(pemData))
	if err != nil {
		t.Fatalf("ResolveKeyRing with PEM fallback failed: %v", err)
	}
	if string(ringPEM.Primary().PublicKey) != string(pub1) {
		t.Errorf("expected primary key to match pub1")
	}

	// 4. Invalid fallback key returns error
	_, err = ResolveKeyRing("not-valid-base64-or-pem!")
	if err == nil {
		t.Fatal("expected error for invalid fallback key, got nil")
	}
}

func TestResolveKeyRing_NotFound(t *testing.T) {
	ResetVerificationKeyRing()
	t.Setenv(EnvPublicKeysPEM, "")
	t.Setenv(EnvPublicKey, "")
	t.Setenv(EnvPublicKeyFile, "")

	// When default system path does not exist
	if _, err := os.Stat(DefaultPublicKeyPath); os.IsNotExist(err) {
		ring, err := ResolveKeyRing()
		if ring != nil {
			t.Errorf("expected nil KeyRing, got %v", ring)
		}
		if !errors.Is(err, ErrPublicKeyNotFound) {
			t.Errorf("expected errors.Is ErrPublicKeyNotFound, got %v", err)
		}
		if !errors.Is(err, ErrMissingPublicKey) {
			t.Errorf("expected errors.Is ErrMissingPublicKey, got %v", err)
		}

		_, errPub := ResolvePublicKey()
		if !errors.Is(errPub, ErrPublicKeyNotFound) {
			t.Errorf("expected ResolvePublicKey to fail with ErrPublicKeyNotFound, got %v", errPub)
		}
	}
}

func TestValidator_NewValidatorConstructors(t *testing.T) {
	ResetVerificationKeyRing()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pemBytes, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("EncodePublicKeyToPEM failed: %v", err)
	}
	b64Key := EncodePublicKeyToBase64(pub)

	// Issue a test token
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	signer = signer.WithKeyID("test-key-id")
	claims := Claims{
		Customer: Customer{Name: "Test Customer"},
		Product:  "test-product",
	}
	token, err := signer.SignArmored(claims)
	if err != nil {
		t.Fatalf("SignArmored failed: %v", err)
	}

	// 1. NewValidatorFromEmbeddedPEM
	vEmbed, err := NewValidatorFromEmbeddedPEM(pemBytes, WithProduct("test-product"))
	if err != nil {
		t.Fatalf("NewValidatorFromEmbeddedPEM failed: %v", err)
	}
	if _, err := vEmbed.Verify(token); err != nil {
		t.Errorf("vEmbed.Verify failed: %v", err)
	}

	// 2. NewValidatorFromBase64
	vB64, err := NewValidatorFromBase64(b64Key, WithProduct("test-product"))
	if err != nil {
		t.Fatalf("NewValidatorFromBase64 failed: %v", err)
	}
	if _, err := vB64.Verify(token); err != nil {
		t.Errorf("vB64.Verify failed: %v", err)
	}

	// 3. NewValidatorWithFallbackKey
	t.Setenv(EnvPublicKeysPEM, "")
	t.Setenv(EnvPublicKey, "")
	t.Setenv(EnvPublicKeyFile, "")

	vFallback, err := NewValidatorWithFallbackKey(b64Key, WithProduct("test-product"))
	if err != nil {
		t.Fatalf("NewValidatorWithFallbackKey failed: %v", err)
	}
	if _, err := vFallback.Verify(token); err != nil {
		t.Errorf("vFallback.Verify failed: %v", err)
	}

	// 4. NewValidatorFromEnv
	t.Setenv(EnvPublicKey, b64Key)
	vEnv, err := NewValidatorFromEnv(WithProduct("test-product"))
	if err != nil {
		t.Fatalf("NewValidatorFromEnv failed: %v", err)
	}
	if _, err := vEnv.Verify(token); err != nil {
		t.Errorf("vEnv.Verify failed: %v", err)
	}
}
