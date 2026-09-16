package license

import (
	"context"
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

func TestHostResolver_Metadata(t *testing.T) {
	resolver := NewHostResolver()
	if resolver.Name() != "host-hardware" {
		t.Errorf("expected name 'host-hardware', got %q", resolver.Name())
	}
	if resolver.Platform() != PlatformHost {
		t.Errorf("expected platform %v, got %v", PlatformHost, resolver.Platform())
	}
}
