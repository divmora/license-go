package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// ProtocolPrefixRelease is the wire format protocol prefix for Divmora Release Attestations.
	ProtocolPrefixRelease = "DIVREL1"

	// PEMTypeReleaseAttestation is the PEM block type for armored release attestations.
	PEMTypeReleaseAttestation = "DIVMORA RELEASE ATTESTATION"
)

// ReleaseClaims represents the cryptographically signed release and build provenance metadata
// minted by the software vendor's authorized CI/CD release pipeline.
type ReleaseClaims struct {
	// Product identifies the software product (e.g. "gitlab-fleet-governor", "otel-aws-log-processor").
	Product string `json:"product"`

	// Version is the official release SemVer string (e.g. "v1.2.0", "1.2.0").
	Version string `json:"version"`

	// GitCommit is the official Git commit SHA (full or short SHA).
	GitCommit string `json:"git_commit,omitempty"`

	// BuildDate is the compilation timestamp when the official release was built.
	BuildDate time.Time `json:"build_date"`

	// ReleaseDate is the initial public release anchor date for BSL 1.1 Change Date calculations.
	ReleaseDate time.Time `json:"release_date"`

	// BinaryDigest is the SHA-256 hash of the compiled release binary (formatted as "sha256:<hex>").
	BinaryDigest string `json:"binary_digest,omitempty"`

	// Authority identifies the issuing entity or release pipeline (e.g. "divmora.com/release").
	Authority string `json:"authority,omitempty"`

	// KeyID identifies the signing key used to issue this release attestation.
	KeyID string `json:"kid,omitempty"`

	// IssuedAt is the timestamp when the attestation token was minted.
	IssuedAt time.Time `json:"issued_at"`

	// Metadata contains arbitrary custom release details (e.g. builder image, pipeline ID).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate asserts that the essential release metadata fields are present and valid.
func (r *ReleaseClaims) Validate() error {
	if strings.TrimSpace(r.Product) == "" {
		return errors.New("license: release attestation missing required 'product'")
	}
	if strings.TrimSpace(r.Version) == "" {
		return errors.New("license: release attestation missing required 'version'")
	}
	if r.BuildDate.IsZero() && r.ReleaseDate.IsZero() {
		return errors.New("license: release attestation must specify BuildDate or ReleaseDate")
	}
	return nil
}

// NormalizedVersion returns the SemVer version string stripped of leading 'v'/'V'.
func (r *ReleaseClaims) NormalizedVersion() string {
	return cleanVersionString(r.Version)
}

// MatchesVersion checks whether a running binary version matches the release attestation.
func (r *ReleaseClaims) MatchesVersion(runningVersion string) bool {
	if runningVersion == "" {
		return true
	}
	return cleanVersionString(r.Version) == cleanVersionString(runningVersion)
}

// MatchesCommit checks whether a running git commit matches the release attestation commit.
func (r *ReleaseClaims) MatchesCommit(runningCommit string) bool {
	if runningCommit == "" || r.GitCommit == "" {
		return true
	}
	c1 := strings.ToLower(strings.TrimSpace(r.GitCommit))
	c2 := strings.ToLower(strings.TrimSpace(runningCommit))
	if c1 == c2 {
		return true
	}
	// Support prefix matching (e.g. short SHA matching full SHA)
	return strings.HasPrefix(c1, c2) || strings.HasPrefix(c2, c1)
}

// MatchesDigest checks whether a computed binary digest matches the attested BinaryDigest.
func (r *ReleaseClaims) MatchesDigest(computedDigest string) bool {
	if r.BinaryDigest == "" || computedDigest == "" {
		return true
	}
	d1 := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.BinaryDigest)), "sha256:")
	d2 := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(computedDigest)), "sha256:")
	return d1 == d2
}

// FormatInspect returns a standardized multi-line terminal inspection output
// of the release attestation metadata.
func (r *ReleaseClaims) FormatInspect() string {
	if r == nil {
		return "No release claims to inspect\n"
	}

	var b strings.Builder
	headerDivider := strings.Repeat("=", 80)

	b.WriteString(headerDivider + "\n")
	b.WriteString("DIVMORA RELEASE ATTESTATION CLAIMS\n")
	b.WriteString(headerDivider + "\n")

	fmt.Fprintf(&b, "%-24s %s\n", "Product:", r.Product)
	fmt.Fprintf(&b, "%-24s %s\n", "Version:", r.Version)
	if r.Authority != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Issuing Authority:", r.Authority)
	}
	if r.KeyID != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Signing Key ID:", r.KeyID)
	}
	if r.GitCommit != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Git Commit:", r.GitCommit)
	}
	if !r.BuildDate.IsZero() {
		fmt.Fprintf(&b, "%-24s %s\n", "Build Date:", r.BuildDate.UTC().Format(time.RFC3339))
	}
	if !r.ReleaseDate.IsZero() {
		fmt.Fprintf(&b, "%-24s %s\n", "BSL Release Date:", r.ReleaseDate.UTC().Format(time.RFC3339))
	}
	if r.BinaryDigest != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Binary Digest:", r.BinaryDigest)
	}
	if !r.IssuedAt.IsZero() {
		fmt.Fprintf(&b, "%-24s %s\n", "Attestation Issued:", r.IssuedAt.UTC().Format(time.RFC3339))
	}

	if len(r.Metadata) > 0 {
		b.WriteString("\nRELEASE METADATA\n")
		metaKeys := make([]string, 0, len(r.Metadata))
		for k := range r.Metadata {
			metaKeys = append(metaKeys, k)
		}
		sort.Strings(metaKeys)
		for _, k := range metaKeys {
			fmt.Fprintf(&b, "  • %-22s %s\n", k+":", r.Metadata[k])
		}
	}

	b.WriteString(headerDivider + "\n")
	return b.String()
}

// ReleaseProvenance reports the result of cryptographic release verification and build provenance evaluation.
type ReleaseProvenance struct {
	// Attested indicates whether the binary release is verified by a trusted cryptographic attestation.
	Attested bool

	// Claims contains the verified release claims, or nil if un-attested.
	Claims *ReleaseClaims

	// VerifiedByKeyID identifies the Key ID in the KeyRing that signed the attestation.
	VerifiedByKeyID string

	// VerifiedKeyStatus indicates the lifecycle status of the verifying key.
	VerifiedKeyStatus KeyStatus

	// Authority identifies the issuing entity.
	Authority string

	// DigestMatched indicates whether the binary's SHA-256 checksum matched the attested digest.
	DigestMatched bool

	// Tampered indicates whether running binary build metadata contradicted the attested release claims.
	Tampered bool

	// TamperReason describes why tampering was flagged.
	TamperReason string
}

// ProvenanceParams specifies the runtime parameters of a binary to evaluate against release claims.
type ProvenanceParams struct {
	// ExpectedProduct is the software product name to assert.
	ExpectedProduct string

	// CurrentVersion is the running binary version (injected via ldflags).
	CurrentVersion string

	// CurrentCommit is the running binary Git commit (injected via ldflags).
	CurrentCommit string

	// CurrentBuildDate is the running binary build timestamp (injected via ldflags).
	CurrentBuildDate time.Time

	// CurrentReleaseDate is the running binary release timestamp (e.g. from BSL policy).
	CurrentReleaseDate time.Time

	// BinaryPath is the path to the running executable on disk (for SHA-256 digest verification).
	BinaryPath string

	// BinaryBytes contains binary executable bytes in-memory (alternative to BinaryPath).
	BinaryBytes []byte
}

// ComputeBytesDigest computes the SHA-256 digest of byte slice, returning "sha256:<hex>".
func ComputeBytesDigest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ComputeReaderDigest computes the SHA-256 digest of data read from an io.Reader, returning "sha256:<hex>".
func ComputeReaderDigest(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("failed to read data for digest computation: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeFileDigest opens a file and computes its SHA-256 digest, returning "sha256:<hex>".
func ComputeFileDigest(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file for digest: %w", err)
	}
	defer f.Close()
	return ComputeReaderDigest(f)
}

// EncodeReleaseToken serializes payload JSON and Ed25519 signature into a compact DIVREL1 token.
func EncodeReleaseToken(payloadJSON, sig []byte) string {
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf("%s.%s.%s", ProtocolPrefixRelease, payloadB64, sigB64)
}

// EncodeReleaseArmored serializes a compact DIVREL1 token into an armored PEM block.
func EncodeReleaseArmored(payloadJSON, sig []byte) string {
	token := EncodeReleaseToken(payloadJSON, sig)
	block := &pem.Block{
		Type:  PEMTypeReleaseAttestation,
		Bytes: []byte(token),
	}
	return string(pem.EncodeToMemory(block))
}

// ParseReleaseToken unpacks an armored PEM block or compact DIVREL1 token.
// Returns the payload JSON, signature bytes, and canonical signed data.
func ParseReleaseToken(rawToken string) (payloadJSON, sig, signedData []byte, err error) {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, nil, nil, fmt.Errorf("%w: empty release token", ErrInvalidReleaseAttestation)
	}

	// 1. Check for armored PEM block
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, nil, nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidReleaseAttestation)
		}
		if block.Type != PEMTypeReleaseAttestation {
			return nil, nil, nil, fmt.Errorf("%w: unexpected PEM block type %q, expected %q",
				ErrInvalidReleaseAttestation, block.Type, PEMTypeReleaseAttestation)
		}
		trimmed = strings.TrimSpace(string(block.Bytes))
	}

	// 2. Compact format: DIVREL1.<payloadB64>.<sigB64>
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: expected 3 dot-separated segments, got %d",
			ErrInvalidReleaseAttestation, len(parts))
	}

	if parts[0] != ProtocolPrefixRelease {
		return nil, nil, nil, fmt.Errorf("%w: invalid protocol prefix %q, expected %q",
			ErrInvalidReleaseAttestation, parts[0], ProtocolPrefixRelease)
	}

	payloadJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed to decode base64 payload: %v",
			ErrInvalidReleaseAttestation, err)
	}

	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed to decode base64 signature: %v",
			ErrInvalidReleaseAttestation, err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, nil, nil, fmt.Errorf("%w: signature length is %d bytes, expected %d",
			ErrInvalidReleaseAttestation, len(sig), ed25519.SignatureSize)
	}

	// Canonical signed data is "DIVREL1.<payloadB64>"
	signedData = []byte(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	return payloadJSON, sig, signedData, nil
}

// SignRelease signs the given ReleaseClaims using an Ed25519 private key, returning a compact DIVREL1 token.
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
	canonicalData := []byte(fmt.Sprintf("%s.%s", ProtocolPrefixRelease, payloadB64))

	sig := ed25519.Sign(privKey, canonicalData)
	return EncodeReleaseToken(payloadJSON, sig), nil
}

// SignReleaseArmored signs ReleaseClaims, returning an armored PEM text block.
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

// VerifyRelease verifies a release attestation token or armored block against a trusted KeyRing.
// Returns the verified ReleaseClaims and the KeyEntry that verified the signature.
func VerifyRelease(rawAttestation string, ring *KeyRing) (*ReleaseClaims, *KeyEntry, error) {
	if ring == nil || ring.Count() == 0 {
		return nil, nil, ErrMissingPublicKey
	}

	payloadJSON, sig, signedData, err := ParseReleaseToken(rawAttestation)
	if err != nil {
		return nil, nil, err
	}

	var kidHint string
	var peek struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(payloadJSON, &peek); err == nil {
		kidHint = peek.KeyID
	}

	matchedKey, err := ring.VerifySignature(signedData, sig, kidHint)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidReleaseAttestation, err)
	}

	var claims ReleaseClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse release claims json: %v", ErrInvalidReleaseAttestation, err)
	}

	if err := claims.Validate(); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidReleaseAttestation, err)
	}

	return &claims, matchedKey, nil
}

// EvaluateProvenance evaluates a binary's authenticity, build parameters, and integrity against a release attestation.
func EvaluateProvenance(rawAttestation string, ring *KeyRing, params ProvenanceParams) (*ReleaseProvenance, error) {
	trimmed := strings.TrimSpace(rawAttestation)
	if trimmed == "" {
		return &ReleaseProvenance{
			Attested: false,
		}, nil
	}

	claims, matchedKey, err := VerifyRelease(trimmed, ring)
	if err != nil {
		return nil, err
	}

	prov := &ReleaseProvenance{
		Attested:          true,
		Claims:            claims,
		VerifiedByKeyID:   matchedKey.ID,
		VerifiedKeyStatus: matchedKey.Status,
		Authority:         claims.Authority,
	}

	// 1. Product match assertion
	if params.ExpectedProduct != "" {
		expectedLower := strings.ToLower(strings.TrimSpace(params.ExpectedProduct))
		prodLower := strings.ToLower(strings.TrimSpace(claims.Product))
		if expectedLower != prodLower && prodLower != "*" && prodLower != "all" {
			prov.Tampered = true
			prov.TamperReason = fmt.Sprintf("product mismatch: attestation is for %q, running binary expects %q", claims.Product, params.ExpectedProduct)
			return prov, fmt.Errorf("%w: expected %q, attestation certifies %q", ErrReleaseProductMismatch, params.ExpectedProduct, claims.Product)
		}
	}

	// 2. Version match assertion
	if params.CurrentVersion != "" {
		if !claims.MatchesVersion(params.CurrentVersion) {
			prov.Tampered = true
			prov.TamperReason = fmt.Sprintf("version mismatch: running binary is %q, attested release is %q", params.CurrentVersion, claims.Version)
			return prov, &ReleaseTamperingError{
				Field:    "version",
				Expected: claims.Version,
				Actual:   params.CurrentVersion,
				Reason:   prov.TamperReason,
			}
		}
	}

	// 3. Git commit match assertion
	if params.CurrentCommit != "" && claims.GitCommit != "" {
		if !claims.MatchesCommit(params.CurrentCommit) {
			prov.Tampered = true
			prov.TamperReason = fmt.Sprintf("git commit mismatch: running binary commit %q does not match attested commit %q", params.CurrentCommit, claims.GitCommit)
			return prov, &ReleaseTamperingError{
				Field:    "git_commit",
				Expected: claims.GitCommit,
				Actual:   params.CurrentCommit,
				Reason:   prov.TamperReason,
			}
		}
	}

	// 4. Build Date cross-check: if local build date claims to be significantly older than attested build date
	if !params.CurrentBuildDate.IsZero() && !claims.BuildDate.IsZero() {
		// If running binary claims a build date more than 24h earlier than official build date, flag tampering!
		diff := claims.BuildDate.Sub(params.CurrentBuildDate)
		if diff > 24*time.Hour {
			prov.Tampered = true
			prov.TamperReason = fmt.Sprintf("build date tampered: running binary claims build date %s, but official release was built at %s",
				params.CurrentBuildDate.UTC().Format(time.RFC3339), claims.BuildDate.UTC().Format(time.RFC3339))
			return prov, &ReleaseTamperingError{
				Field:    "build_date",
				Expected: claims.BuildDate.UTC().Format(time.RFC3339),
				Actual:   params.CurrentBuildDate.UTC().Format(time.RFC3339),
				Reason:   prov.TamperReason,
			}
		}
	}

	// 5. Release Date cross-check: if local release date claims to be significantly older than attested release date
	if !params.CurrentReleaseDate.IsZero() && !claims.ReleaseDate.IsZero() {
		// If running binary claims a release date more than 24h earlier than official release date, flag tampering!
		diff := claims.ReleaseDate.Sub(params.CurrentReleaseDate)
		if diff > 24*time.Hour {
			prov.Tampered = true
			prov.TamperReason = fmt.Sprintf("release date tampered: running binary claims release date %s, but official release date is %s",
				params.CurrentReleaseDate.UTC().Format(time.RFC3339), claims.ReleaseDate.UTC().Format(time.RFC3339))
			return prov, &ReleaseTamperingError{
				Field:    "release_date",
				Expected: claims.ReleaseDate.UTC().Format(time.RFC3339),
				Actual:   params.CurrentReleaseDate.UTC().Format(time.RFC3339),
				Reason:   prov.TamperReason,
			}
		}
	}

	// 6. Binary digest assertion
	var computedDigest string
	if len(params.BinaryBytes) > 0 {
		computedDigest = ComputeBytesDigest(params.BinaryBytes)
	} else if params.BinaryPath != "" {
		d, err := ComputeFileDigest(params.BinaryPath)
		if err != nil {
			return prov, fmt.Errorf("failed to compute binary digest from %s: %w", params.BinaryPath, err)
		}
		computedDigest = d
	}

	if computedDigest != "" && claims.BinaryDigest != "" {
		if !claims.MatchesDigest(computedDigest) {
			prov.Tampered = true
			prov.TamperReason = fmt.Sprintf("binary digest mismatch: computed %s, attested %s", computedDigest, claims.BinaryDigest)
			return prov, fmt.Errorf("%w: computed %s does not match attested %s", ErrReleaseDigestMismatch, computedDigest, claims.BinaryDigest)
		}
		prov.DigestMatched = true
	}

	return prov, nil
}

// InspectRelease decodes and returns the ReleaseClaims from a raw or armored release token
// without verifying the cryptographic signature.
func InspectRelease(rawToken string) (*ReleaseClaims, error) {
	payloadJSON, _, _, err := ParseReleaseToken(rawToken)
	if err != nil {
		return nil, err
	}

	var claims ReleaseClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse release claims json: %v", ErrInvalidReleaseAttestation, err)
	}

	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReleaseAttestation, err)
	}

	return &claims, nil
}

// InspectReleaseFromFile reads a release attestation file and unpacks claims without signature verification.
func InspectReleaseFromFile(filePath string) (*ReleaseClaims, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read release attestation file %s: %w", filePath, err)
	}
	return InspectRelease(string(data))
}
