package issuer

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/divmora/license-go/pkg/license"
)

const (
	// PEMTypePrivateKey is the PEM block type for PKCS#8 private keys.
	PEMTypePrivateKey = "PRIVATE KEY"
)

// EncodePrivateKeyToPEM marshals an Ed25519 private key into PKCS#8 PEM format.
func EncodePrivateKeyToPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) == 0 {
		return nil, license.ErrMissingPrivateKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	block := &pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// ParsePrivateKeyFromPEM parses a PKCS#8 PEM-encoded Ed25519 private key.
func ParsePrivateKeyFromPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	privKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T, expected Ed25519", key)
	}
	return privKey, nil
}
