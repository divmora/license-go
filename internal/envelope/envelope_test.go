package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"id":"lic_123","product":"gitlab-fleet-governor"}`)
	sig := ed25519.Sign(priv, []byte("DIV1."+string(payload)))

	token := EncodeToken(payload, sig)
	if !strings.HasPrefix(token, "DIV1.") {
		t.Fatalf("expected DIV1. prefix, got %s", token)
	}

	armored := WrapArmored(token)
	if !strings.Contains(armored, ArmoredHeader) || !strings.Contains(armored, ArmoredFooter) {
		t.Fatalf("missing armored markers: %s", armored)
	}

	armoredDirect := EncodeArmored(payload, sig)
	if !strings.Contains(armoredDirect, ArmoredHeader) || !strings.Contains(armoredDirect, ArmoredFooter) {
		t.Fatalf("missing armored markers in EncodeArmored: %s", armoredDirect)
	}

	unwrapped, err := UnwrapToken(armored)
	if err != nil {
		t.Fatalf("UnwrapToken failed: %v", err)
	}
	if unwrapped != token {
		t.Fatalf("unwrapped token mismatch: got %s, want %s", unwrapped, token)
	}

	parsedPayload, parsedSig, signedData, err := ParseToken(armored)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}
	if string(parsedPayload) != string(payload) {
		t.Fatalf("payload mismatch: got %s, want %s", string(parsedPayload), string(payload))
	}
	if len(parsedSig) != ed25519.SignatureSize {
		t.Fatalf("sig size mismatch: got %d, want %d", len(parsedSig), ed25519.SignatureSize)
	}
	if !strings.HasPrefix(string(signedData), "DIV1.") {
		t.Fatalf("signedData mismatch: %s", string(signedData))
	}
}

func TestEnvelopeErrors(t *testing.T) {
	// Empty string
	_, err := UnwrapToken("")
	if !errors.Is(err, ErrLicenseNotFound) {
		t.Fatalf("expected ErrLicenseNotFound, got %v", err)
	}

	// Incomplete boundary
	_, err = UnwrapToken(ArmoredHeader + "\ntoken")
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Fatalf("expected ErrInvalidLicenseFormat, got %v", err)
	}

	// Invalid signature length
	badToken := "DIV1.e30.YWJj" // signature is "abc"
	_, _, _, err = ParseToken(badToken)
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Fatalf("expected ErrInvalidLicenseFormat, got %v", err)
	}

	// Malformed boundary markers (footer before header)
	_, err = UnwrapToken(ArmoredFooter + "\nsome content\n" + ArmoredHeader)
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Errorf("expected ErrInvalidLicenseFormat for reversed markers, got %v", err)
	}

	// Empty inner armored content
	_, err = UnwrapToken(ArmoredHeader + "\n  \t \n" + ArmoredFooter)
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Errorf("expected ErrInvalidLicenseFormat for empty inner payload, got %v", err)
	}

	// Fewer than 3 segments
	_, _, _, err = ParseToken("DIV1.onlyone")
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Errorf("expected ErrInvalidLicenseFormat for 2 segments, got %v", err)
	}

	// Unsupported token version
	_, _, _, err = ParseToken("DIV2.e30.c2ln")
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Errorf("expected ErrInvalidLicenseFormat for unsupported version, got %v", err)
	}

	// Invalid payload base64
	_, _, _, err = ParseToken("DIV1.???invalid???.c2ln")
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Errorf("expected ErrInvalidLicenseFormat for invalid payload b64, got %v", err)
	}

	// Invalid signature base64
	_, _, _, err = ParseToken("DIV1.e30.???invalid???")
	if !errors.Is(err, ErrInvalidLicenseFormat) {
		t.Errorf("expected ErrInvalidLicenseFormat for invalid sig b64, got %v", err)
	}

	// Empty string to ParseToken
	_, _, _, err = ParseToken("")
	if !errors.Is(err, ErrLicenseNotFound) {
		t.Errorf("expected ErrLicenseNotFound for empty token, got %v", err)
	}
}

func TestEnvelope_PaddedBase64Fallback(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"id":"1"}`)
	sig := ed25519.Sign(priv, []byte("DIV1."+string(payload)))

	// Force standard URL encoding with padding '='
	pB64 := strings.Repeat("A", 4) // padded if length % 4 != 0
	_ = pB64
	// Let's create a padded token manually
	payloadPadded := base64.URLEncoding.EncodeToString(payload)
	sigPadded := base64.URLEncoding.EncodeToString(sig)
	paddedToken := "DIV1." + payloadPadded + "." + sigPadded

	parsedPayload, parsedSig, _, err := ParseToken(paddedToken)
	if err != nil {
		t.Fatalf("ParseToken with padded base64 failed: %v", err)
	}
	if string(parsedPayload) != string(payload) {
		t.Errorf("payload mismatch: got %s, want %s", string(parsedPayload), string(payload))
	}
	if len(parsedSig) != ed25519.SignatureSize {
		t.Errorf("sig size mismatch: got %d, want %d", len(parsedSig), ed25519.SignatureSize)
	}
}
