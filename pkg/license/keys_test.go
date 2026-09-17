package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyPairGenerationAndPEMEncoding(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("unexpected public key length: %d", len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("unexpected private key length: %d", len(priv))
	}

	// Private key round-trip
	privPEM, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM failed: %v", err)
	}

	parsedPriv, err := ParsePrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM failed: %v", err)
	}
	if !priv.Equal(parsedPriv) {
		t.Fatal("parsed private key does not match original")
	}

	// Public key round-trip
	pubPEM, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("EncodePublicKeyToPEM failed: %v", err)
	}

	parsedPub, err := ParsePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM failed: %v", err)
	}
	if !pub.Equal(parsedPub) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestPublicKeyBase64(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	b64 := EncodePublicKeyToBase64(pub)
	parsedPub, err := ParsePublicKeyFromBase64(b64)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromBase64 failed: %v", err)
	}

	if !pub.Equal(parsedPub) {
		t.Fatal("base64 decoded public key does not match original")
	}
}

func TestKeyFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	privFile := filepath.Join(tempDir, "test_private.pem")
	pubFile := filepath.Join(tempDir, "test_public.pem")

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if err := SavePrivateKeyToPEMFile(priv, privFile, 0600); err != nil {
		t.Fatalf("SavePrivateKeyToPEMFile failed: %v", err)
	}

	info, err := os.Stat(privFile)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}

	if err := SavePublicKeyToPEMFile(pub, pubFile, 0644); err != nil {
		t.Fatalf("SavePublicKeyToPEMFile failed: %v", err)
	}

	loadedPriv, err := LoadPrivateKeyFromPEMFile(privFile)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEMFile failed: %v", err)
	}
	if !priv.Equal(loadedPriv) {
		t.Fatal("loaded private key does not match original")
	}

	loadedPub, err := LoadPublicKeyFromPEMFile(pubFile)
	if err != nil {
		t.Fatalf("LoadPublicKeyFromPEMFile failed: %v", err)
	}
	if !pub.Equal(loadedPub) {
		t.Fatal("loaded public key does not match original")
	}
}

func TestKeyFingerprint_128BitAndShort(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	fp := KeyFingerprint(pub)
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("expected sha256: prefix, got: %s", fp)
	}
	// "sha256:" is 7 chars. 16 bytes in hex is 32 chars -> total 39 chars (128 bits)
	if len(fp) != 7+32 {
		t.Errorf("expected 128-bit hex fingerprint length 39 (7+32), got %d (%s)", len(fp), fp)
	}

	shortFP := KeyFingerprintShort(pub)
	if !strings.HasPrefix(shortFP, "sha256:") {
		t.Fatalf("expected sha256: prefix, got: %s", shortFP)
	}
	// "sha256:" is 7 chars. 8 bytes in hex is 16 chars -> total 23 chars (64 bits)
	if len(shortFP) != 7+16 {
		t.Errorf("expected 64-bit hex fingerprint length 23 (7+16), got %d (%s)", len(shortFP), shortFP)
	}

	// shortFP should be prefix of fp
	if !strings.HasPrefix(fp, shortFP) {
		t.Errorf("expected %s to be a prefix of %s", shortFP, fp)
	}

	// Invalid pub key
	if KeyFingerprint(nil) != "" {
		t.Error("expected empty string for nil key")
	}
	if KeyFingerprintShort(nil) != "" {
		t.Error("expected empty string for nil key")
	}
}

func TestKeyRing_FingerprintCompatibilityLookup(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kr := NewKeyRing(pub)
	entry := kr.Primary()

	fp128 := KeyFingerprint(pub)
	fp64 := KeyFingerprintShort(pub)

	found128, ok := kr.FindKey(fp128)
	if !ok || found128 != entry {
		t.Errorf("failed to find key by 128-bit fingerprint %s", fp128)
	}

	found64, ok := kr.FindKey(fp64)
	if !ok || found64 != entry {
		t.Errorf("failed to find key by legacy 64-bit fingerprint %s", fp64)
	}

	foundByFP64, ok := kr.FindKeyByFingerprint(fp64)
	if !ok || foundByFP64 != entry {
		t.Errorf("failed to find key by FindKeyByFingerprint with 64-bit %s", fp64)
	}
}

func TestKeys_ParsePublicKeyFromBase64Variants(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 1. StdEncoding raw 32 bytes
	b64Std := base64.StdEncoding.EncodeToString(pub)
	parsed1, err := ParsePublicKeyFromBase64(b64Std)
	if err != nil || !parsed1.Equal(pub) {
		t.Fatalf("ParsePublicKeyFromBase64(b64Std) error=%v, parsed=%v", err, parsed1)
	}

	// 2. RawURLEncoding raw 32 bytes
	b64URL := base64.RawURLEncoding.EncodeToString(pub)
	parsed2, err := ParsePublicKeyFromBase64(b64URL)
	if err != nil || !parsed2.Equal(pub) {
		t.Fatalf("ParsePublicKeyFromBase64(b64URL) error=%v, parsed=%v", err, parsed2)
	}

	// 3. PKIX DER base64
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	b64DER := base64.StdEncoding.EncodeToString(derBytes)
	parsed3, err := ParsePublicKeyFromBase64(b64DER)
	if err != nil || !parsed3.Equal(pub) {
		t.Fatalf("ParsePublicKeyFromBase64(b64DER) error=%v, parsed=%v", err, parsed3)
	}

	// 4. Invalid base64
	if _, err := ParsePublicKeyFromBase64("!@#$%^&*"); err == nil {
		t.Error("expected error for invalid base64, got nil")
	}

	// 5. Invalid DER content
	if _, err := ParsePublicKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("not a valid der format of any kind"))); err == nil {
		t.Error("expected error for invalid der, got nil")
	}
}

func TestKeys_PEMErrorBranches(t *testing.T) {
	// 1. EncodePublicKeyToPEM with nil
	if _, err := EncodePublicKeyToPEM(nil); !errors.Is(err, ErrMissingPublicKey) {
		t.Errorf("expected ErrMissingPublicKey, got %v", err)
	}

	// 2. ParsePublicKeyFromPEM with non-PEM
	if _, err := ParsePublicKeyFromPEM([]byte("not a pem")); err == nil {
		t.Error("expected error for invalid PEM bytes")
	}

	// 3. ParsePublicKeyFromPEM with invalid PKIX DER block
	block := &pem.Block{Type: PEMTypePublicKey, Bytes: []byte("invalid-pkix-bytes")}
	if _, err := ParsePublicKeyFromPEM(pem.EncodeToMemory(block)); err == nil {
		t.Error("expected error for invalid PKIX DER")
	}

	// 4. EncodePublicKeysToPEM with empty slice
	if _, err := EncodePublicKeysToPEM([]ed25519.PublicKey{}); err == nil {
		t.Error("expected error for empty public keys slice")
	}

	// 5. EncodePublicKeysToPEM with slice containing nil key
	if _, err := EncodePublicKeysToPEM([]ed25519.PublicKey{nil}); err == nil {
		t.Error("expected error for nil key in EncodePublicKeysToPEM")
	}
}
