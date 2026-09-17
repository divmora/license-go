package issuer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/divmora/license-go/pkg/license"
)

// SignRelease signs the given ReleaseClaims using an Ed25519 private key, returning a compact DIVREL1 token.
func SignRelease(claims license.ReleaseClaims, privKey ed25519.PrivateKey, opts ...SignerOption) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", license.ErrMissingPrivateKey
	}

	if err := claims.Validate(); err != nil {
		return "", err
	}

	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC()
	}

	// Apply optional signer configurations
	var s Signer
	for _, opt := range opts {
		opt(&s)
	}
	if claims.KeyID == "" && s.keyID != "" {
		claims.KeyID = s.keyID
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal release claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	canonicalData := []byte(fmt.Sprintf("%s.%s", license.ProtocolPrefixRelease, payloadB64))

	sig := ed25519.Sign(privKey, canonicalData)
	return license.EncodeReleaseToken(payloadJSON, sig), nil
}

// SignReleaseArmored signs ReleaseClaims, returning an armored PEM text block.
func SignReleaseArmored(claims license.ReleaseClaims, privKey ed25519.PrivateKey, opts ...SignerOption) (string, error) {
	token, err := SignRelease(claims, privKey, opts...)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  license.PEMTypeReleaseAttestation,
		Bytes: []byte(token),
	}
	return string(pem.EncodeToMemory(block)), nil
}
