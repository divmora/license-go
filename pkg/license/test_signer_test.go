package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// The functions in this file are TEST-ONLY helpers for testing license verification in pkg/license.
// They are excluded from production builds and never exposed to downstream consumers.

const (
	// PEMTypePrivateKey is the PEM block type for PKCS#8 private keys in tests.
	PEMTypePrivateKey = "PRIVATE KEY"
)

// GenerateKeyPair generates an Ed25519 key pair for testing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// EncodePrivateKeyToPEM marshals an Ed25519 private key into PKCS#8 PEM format for testing.
func EncodePrivateKeyToPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) == 0 {
		return nil, ErrMissingPrivateKey
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

// ParsePrivateKeyFromPEM parses a PKCS#8 PEM-encoded Ed25519 private key for testing.
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

// SavePrivateKeyToPEMFile writes an Ed25519 private key to a PEM file for testing.
func SavePrivateKeyToPEMFile(priv ed25519.PrivateKey, filePath string, perm os.FileMode) error {
	pemData, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, pemData, perm)
}

// LoadPrivateKeyFromPEMFile reads and parses an Ed25519 private key from a PEM file for testing.
func LoadPrivateKeyFromPEMFile(filePath string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	return ParsePrivateKeyFromPEM(data)
}

// SignerOption is a functional option for configuring a Signer in tests.
type SignerOption func(*Signer)

// WithSignerKeyID configures the default Key ID to embed in signed license claims in tests.
func WithSignerKeyID(kid string) SignerOption {
	return func(s *Signer) {
		s.keyID = kid
	}
}

// Signer signs license claims using an Ed25519 private key in tests.
type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

// NewSigner creates a new Signer with the provided Ed25519 private key for tests.
func NewSigner(privateKey ed25519.PrivateKey, opts ...SignerOption) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrMissingPrivateKey
	}
	s := &Signer{privateKey: privateKey}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// WithKeyID returns a copy of the Signer configured with the given Key ID for tests.
func (s *Signer) WithKeyID(kid string) *Signer {
	return &Signer{
		privateKey: s.privateKey,
		keyID:      kid,
	}
}

// NewSignerFromPEM creates a new Signer from PKCS#8 PEM-encoded private key bytes for tests.
func NewSignerFromPEM(pemBytes []byte, opts ...SignerOption) (*Signer, error) {
	privKey, err := ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewSigner(privKey, opts...)
}

// NewSignerFromPEMFile creates a new Signer by loading an Ed25519 private key from a file for tests.
func NewSignerFromPEMFile(filePath string, opts ...SignerOption) (*Signer, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	return NewSignerFromPEM(data, opts...)
}

// Sign marshals and signs the given Claims, returning a compact token string for tests.
func (s *Signer) Sign(claims Claims) (string, error) {
	if s.privateKey == nil {
		return "", ErrMissingPrivateKey
	}

	if claims.Customer.Name == "" {
		return "", errors.New("license: customer name cannot be empty")
	}
	if claims.Product == "" {
		return "", errors.New("license: product cannot be empty")
	}

	if claims.ID == "" {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		claims.ID = hex.EncodeToString(bytes)
	}

	if claims.Plan == "" {
		claims.Plan = "standard"
	}

	if claims.KeyID == "" && s.keyID != "" {
		claims.KeyID = s.keyID
	}

	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC()
	}

	if err := claims.ValidateClaimsSchema(); err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal license claims: %w", err)
	}

	tempToken := EncodeToken(payloadJSON, nil)
	dotIdx := len(tempToken) - 1
	signedData := []byte(tempToken[:dotIdx])

	sig := ed25519.Sign(s.privateKey, signedData)
	return EncodeToken(payloadJSON, sig), nil
}

// SignArmored marshals and signs Claims, returning an armored text block for tests.
func (s *Signer) SignArmored(claims Claims) (string, error) {
	token, err := s.Sign(claims)
	if err != nil {
		return "", err
	}
	return WrapArmored(token), nil
}

// SignToFile marshals and signs Claims, saving the result to a specified file for tests.
func (s *Signer) SignToFile(claims Claims, filePath string, armored bool) error {
	var content string
	var err error
	if armored {
		content, err = s.SignArmored(claims)
	} else {
		content, err = s.Sign(claims)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(content), 0644)
}

// SignRelease signs ReleaseClaims using an Ed25519 private key for tests.
func SignRelease(claims ReleaseClaims, privKey ed25519.PrivateKey, opts ...SignerOption) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", ErrMissingPrivateKey
	}

	if err := claims.Validate(); err != nil {
		return "", err
	}

	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC()
	}

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
	canonicalData := []byte(fmt.Sprintf("%s.%s", ProtocolPrefixRelease, payloadB64))

	sig := ed25519.Sign(privKey, canonicalData)
	return EncodeReleaseToken(payloadJSON, sig), nil
}

// SignReleaseArmored signs ReleaseClaims, returning an armored PEM text block for tests.
func SignReleaseArmored(claims ReleaseClaims, privKey ed25519.PrivateKey, opts ...SignerOption) (string, error) {
	token, err := SignRelease(claims, privKey, opts...)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  PEMTypeReleaseAttestation,
		Bytes: []byte(token),
	}
	return string(pem.EncodeToMemory(block)), nil
}
