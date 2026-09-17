package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
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
}
