package license

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestResolveHostFingerprint(t *testing.T) {
	fp, err := ResolveHostFingerprint()
	if err != nil {
		t.Fatalf("ResolveHostFingerprint() error = %v", err)
	}
	if fp == nil {
		t.Fatal("expected non-nil MachineFingerprint")
	}

	if fp.Platform != PlatformHost {
		t.Errorf("expected platform %v, got %v", PlatformHost, fp.Platform)
	}
	if !strings.HasPrefix(fp.Primary, "fp:host:") {
		t.Errorf("expected primary prefix 'fp:host:', got %q", fp.Primary)
	}
	if len(fp.CanonicalDigest) != 64 {
		t.Errorf("expected 64-char canonical digest, got len=%d (%q)", len(fp.CanonicalDigest), fp.CanonicalDigest)
	}
	if len(fp.ShortDigest) != 16 {
		t.Errorf("expected 16-char short digest, got len=%d (%q)", len(fp.ShortDigest), fp.ShortDigest)
	}
	if fp.Components["os"] != runtime.GOOS {
		t.Errorf("expected os %s, got %s", runtime.GOOS, fp.Components["os"])
	}
	if fp.Components["arch"] != runtime.GOARCH {
		t.Errorf("expected arch %s, got %s", runtime.GOARCH, fp.Components["arch"])
	}
	if fp.ResolvedAt.IsZero() {
		t.Error("expected non-zero ResolvedAt")
	}

	summary := fp.FormatSummary()
	if !strings.Contains(summary, string(PlatformHost)) {
		t.Errorf("expected summary to contain platform, got %q", summary)
	}

	// Verify determinism: consecutive resolution yields identical fingerprint
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fp2, err := ResolveHostFingerprintWithContext(ctx)
	if err != nil {
		t.Fatalf("ResolveHostFingerprintWithContext error = %v", err)
	}
	if fp2.Primary != fp.Primary {
		t.Errorf("fingerprint Primary not deterministic: %q vs %q", fp.Primary, fp2.Primary)
	}
	if fp2.CanonicalDigest != fp.CanonicalDigest {
		t.Errorf("fingerprint CanonicalDigest not deterministic: %q vs %q", fp.CanonicalDigest, fp2.CanonicalDigest)
	}
}

func TestMachineFingerprint_Matches(t *testing.T) {
	fp := &MachineFingerprint{
		Primary:         "fp:host:a1b2c3d4e5f67890",
		Platform:        PlatformHost,
		CanonicalDigest: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
		ShortDigest:     "a1b2c3d4e5f67890",
		Components: map[string]string{
			"os":          "linux",
			"arch":        "amd64",
			"system_uuid": "ec2a1b2c-3d4e-5f67-8901-23456789abcd",
			"machine_id":  "fedcba9876543210fedcba9876543210",
		},
		ResolvedAt: time.Now().UTC(),
	}

	tests := []struct {
		name    string
		claimed string
		want    bool
	}{
		{"exact primary", "fp:host:a1b2c3d4e5f67890", true},
		{"case-insensitive primary", "FP:HOST:A1B2C3D4E5F67890", true},
		{"canonical digest", "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0", true},
		{"short digest", "a1b2c3d4e5f67890", true},
		{"sha256 prefix", "sha256:a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0", true},
		{"fp prefix with short digest", "fp:a1b2c3d4e5f67890", true},
		{"fp:host prefix with short digest", "fp:host:a1b2c3d4e5f67890", true},
		{"system_uuid match", "ec2a1b2c-3d4e-5f67-8901-23456789abcd", true},
		{"system_uuid case-insensitive", "EC2A1B2C-3D4E-5F67-8901-23456789ABCD", true},
		{"machine_id match", "fedcba9876543210fedcba9876543210", true},
		{"whitespace tolerance", "  fp:host:a1b2c3d4e5f67890  \n", true},
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"unrelated string", "different-machine-fingerprint", false},
		{"unrelated sha256", "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fp.Matches(tc.claimed)
			if got != tc.want {
				t.Errorf("fp.Matches(%q) = %v; want %v", tc.claimed, got, tc.want)
			}
		})
	}

	// Test nil receiver
	var nilFP *MachineFingerprint
	if nilFP.Matches("fp:host:a1b2c3d4e5f67890") {
		t.Error("nil fingerprint should never match")
	}
	if nilFP.FormatSummary() != "No machine fingerprint" {
		t.Errorf("unexpected nil summary: %q", nilFP.FormatSummary())
	}
}

func TestComputeCanonicalDigest(t *testing.T) {
	comp1 := map[string]string{
		"os":          "linux",
		"arch":        "amd64",
		"system_uuid": "11111111-2222-3333-4444-555555555555",
	}
	digest1, short1 := computeCanonicalDigest(PlatformHost, comp1)
	if len(digest1) != 64 || len(short1) != 16 {
		t.Fatalf("invalid digest lengths: %d, %d", len(digest1), len(short1))
	}
	if !strings.HasPrefix(digest1, short1) {
		t.Errorf("expected short digest %q to be prefix of %q", short1, digest1)
	}

	// Same components must produce identical digest
	digest2, short2 := computeCanonicalDigest(PlatformHost, comp1)
	if digest1 != digest2 || short1 != short2 {
		t.Errorf("computeCanonicalDigest is non-deterministic: %q vs %q", digest1, digest2)
	}

	// Different components produce different digests
	comp3 := map[string]string{
		"os":          "linux",
		"arch":        "amd64",
		"system_uuid": "99999999-8888-7777-6666-555555555555",
	}
	digest3, _ := computeCanonicalDigest(PlatformHost, comp3)
	if digest1 == digest3 {
		t.Errorf("different UUIDs produced colliding digest: %s", digest1)
	}

	// Fallback to MACs and hostname if UUID/machine_id are missing
	compFallback := map[string]string{
		"os":            "linux",
		"arch":          "amd64",
		"mac_addresses": "aa:bb:cc:dd:ee:ff",
		"hostname":      "worker-01.prod.lan",
	}
	digestFB, shortFB := computeCanonicalDigest(PlatformHost, compFallback)
	if len(digestFB) != 64 || len(shortFB) != 16 {
		t.Fatalf("invalid fallback digest lengths: %d, %d", len(digestFB), len(shortFB))
	}
}

func TestComputeCanonicalDigest_AWSLambda(t *testing.T) {
	comp1 := map[string]string{
		"os":            "linux",
		"arch":          "arm64",
		"function_name": "otel-log-forwarder",
		"region":        "us-east-1",
		"account_id":    "123456789012",
		"function_arn":  "arn:aws:lambda:us-east-1:123456789012:function:otel-log-forwarder",
	}
	digest1, short1 := computeCanonicalDigest(PlatformAWSLambda, comp1)
	if len(digest1) != 64 || len(short1) != 16 {
		t.Fatalf("invalid digest lengths: %d, %d", len(digest1), len(short1))
	}
	if !strings.HasPrefix(digest1, short1) {
		t.Errorf("expected short digest %q to be prefix of %q", short1, digest1)
	}

	// Determinism
	digest2, short2 := computeCanonicalDigest(PlatformAWSLambda, comp1)
	if digest1 != digest2 || short1 != short2 {
		t.Errorf("computeCanonicalDigest non-deterministic: %q vs %q", digest1, digest2)
	}

	// Distinct functions produce different digests
	comp2 := map[string]string{
		"os":            "linux",
		"arch":          "arm64",
		"function_name": "billing-processor",
		"region":        "us-east-1",
		"account_id":    "123456789012",
	}
	digest3, _ := computeCanonicalDigest(PlatformAWSLambda, comp2)
	if digest1 == digest3 {
		t.Errorf("different function names produced colliding digest: %s", digest1)
	}
}

func TestMachineFingerprint_Matches_AWSLambda(t *testing.T) {
	comp := map[string]string{
		"os":            "linux",
		"arch":          "arm64",
		"function_name": "otel-log-forwarder",
		"region":        "us-east-1",
		"account_id":    "123456789012",
		"function_arn":  "arn:aws:lambda:us-east-1:123456789012:function:otel-log-forwarder",
	}
	digest, short := computeCanonicalDigest(PlatformAWSLambda, comp)
	fp := &MachineFingerprint{
		Primary:         "fp:lambda:" + short,
		Platform:        PlatformAWSLambda,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      comp,
		ResolvedAt:      time.Now().UTC(),
	}

	tests := []struct {
		name    string
		claimed string
		want    bool
	}{
		{"exact primary", "fp:lambda:" + short, true},
		{"case-insensitive primary", "FP:LAMBDA:" + strings.ToUpper(short), true},
		{"canonical digest", digest, true},
		{"short digest", short, true},
		{"prefix fp:lambda: with short", "fp:lambda:" + short, true},
		{"function_name match", "otel-log-forwarder", true},
		{"function_name case-insensitive", "OTEL-LOG-FORWARDER", true},
		{"function_arn match", "arn:aws:lambda:us-east-1:123456789012:function:otel-log-forwarder", true},
		{"whitespace tolerance", "  otel-log-forwarder  ", true},
		{"mismatched function", "other-function", false},
		{"mismatched digest", "0000000000000000", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fp.Matches(tc.claimed)
			if got != tc.want {
				t.Errorf("fp.Matches(%q) = %v, want %v", tc.claimed, got, tc.want)
			}
		})
	}
}

func TestHostResolver_Metadata(t *testing.T) {
	resolver := NewHostResolver()
	if resolver.Name() != "host-hardware" {
		t.Errorf("expected name 'host-hardware', got %q", resolver.Name())
	}
	if resolver.Platform() != PlatformHost {
		t.Errorf("expected platform %v, got %v", PlatformHost, resolver.Platform())
	}
}

func TestValidator_AutoFingerprint_Match(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Resolve local host machine fingerprint
	localFP, err := ResolveHostFingerprint()
	if err != nil {
		t.Fatalf("failed to resolve local host fingerprint: %v", err)
	}

	// Issue license locked to local machine fingerprint
	claims := Claims{
		Customer:    Customer{Name: "Acme Corp"},
		Product:     "gitlab-fleet-governor",
		Fingerprint: localFP.Primary,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Validator with WithAutoFingerprint(true)
	val, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithAutoFingerprint(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := val.VerifyWithResult(token)
	if err != nil {
		t.Fatalf("VerifyWithResult() failed unexpectedly: %v", err)
	}

	if !res.FingerprintMatched {
		t.Error("expected FingerprintMatched == true")
	}
	if res.ResolvedFingerprint == nil {
		t.Fatal("expected non-nil ResolvedFingerprint in result")
	}
	if res.ResolvedFingerprint.Primary != localFP.Primary {
		t.Errorf("ResolvedFingerprint.Primary = %q, want %q", res.ResolvedFingerprint.Primary, localFP.Primary)
	}
}

func TestValidator_AutoFingerprint_Mismatch(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Issue license locked to a different machine fingerprint
	claims := Claims{
		Customer:    Customer{Name: "Acme Corp"},
		Product:     "gitlab-fleet-governor",
		Fingerprint: "fp:host:0000000000000000",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	val, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithAutoFingerprint(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = val.VerifyWithResult(token)
	if err == nil {
		t.Fatal("expected ErrFingerprintMismatch, got nil")
	}
	if !strings.Contains(err.Error(), "does not match license bound to") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidator_AutoFingerprint_CustomResolver(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	mockFP := &MachineFingerprint{
		Primary:         "fp:k8s:aabbccddeeff0011",
		Platform:        PlatformKubernetes,
		CanonicalDigest: "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
		ShortDigest:     "aabbccddeeff0011",
		Components: map[string]string{
			"cluster_uid": "mock-k8s-uid-9999",
		},
	}

	mock := &mockResolver{
		name:     "custom-k8s",
		platform: PlatformKubernetes,
		fp:       mockFP,
	}

	claims := Claims{
		Customer:    Customer{Name: "Acme Corp"},
		Product:     "gitlab-fleet-governor",
		Fingerprint: "mock-k8s-uid-9999",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	val, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithAutoFingerprint(true),
		WithFingerprintResolver(mock),
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := val.VerifyWithResult(token)
	if err != nil {
		t.Fatalf("expected custom resolver match, got error: %v", err)
	}
	if !res.FingerprintMatched {
		t.Error("expected FingerprintMatched == true")
	}
	if res.ResolvedFingerprint.Primary != mockFP.Primary {
		t.Errorf("ResolvedFingerprint.Primary = %q, want %q", res.ResolvedFingerprint.Primary, mockFP.Primary)
	}
}

func TestValidator_RequireFingerprint(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Floating license without fingerprint
	claims := Claims{
		Customer:  Customer{Name: "Acme Corp"},
		Product:   "gitlab-fleet-governor",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	val, err := NewValidator(pub,
		WithProduct("gitlab-fleet-governor"),
		WithRequireFingerprint(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = val.VerifyWithResult(token)
	if err == nil {
		t.Fatal("expected ErrFingerprintMismatch on missing fingerprint, got nil")
	}
}

func TestValidator_AutoFingerprint_AWSLambda(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Issue license locked to specific Lambda function name
	claims := Claims{
		Customer:    Customer{Name: "Acme Cloud"},
		Product:     "otel-aws-log-processor",
		Fingerprint: "otel-aws-log-processor-prod",
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Set environment for Lambda
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "otel-aws-log-processor-prod")
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
	t.Setenv("AWS_REGION", "us-east-1")

	val, err := NewValidator(pub,
		WithProduct("otel-aws-log-processor"),
		WithAutoFingerprint(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := val.VerifyWithResult(token)
	if err != nil {
		t.Fatalf("expected successful validation in Lambda, got error: %v", err)
	}
	if !res.FingerprintMatched {
		t.Error("expected FingerprintMatched == true")
	}
	if res.ResolvedFingerprint == nil || res.ResolvedFingerprint.Platform != PlatformAWSLambda {
		t.Fatalf("expected ResolvedFingerprint platform aws-lambda, got: %v", res.ResolvedFingerprint)
	}

	// Mismatched Lambda function name
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "different-unauthorized-lambda")
	_, err = val.VerifyWithResult(token)
	if err == nil {
		t.Fatal("expected ErrFingerprintMismatch for different lambda function name, got nil")
	}
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("expected ErrFingerprintMismatch, got %v", err)
	}
}
