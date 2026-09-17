package resolvers

import (
	"context"
	"testing"
)

func TestHostResolver(t *testing.T) {
	resolver := NewHostResolver()
	if resolver.Name() != "host-hardware" {
		t.Errorf("expected name 'host-hardware', got %s", resolver.Name())
	}
	if resolver.Platform() != PlatformHost {
		t.Errorf("expected platform 'host', got %s", resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("HostResolver.Resolve failed: %v", err)
	}

	if fp.Platform != PlatformHost {
		t.Errorf("expected PlatformHost, got %s", fp.Platform)
	}
	if fp.Primary == "" {
		t.Error("expected non-empty Primary digest")
	}
	if !fp.Matches(fp.Primary) {
		t.Errorf("expected fp to match its own primary: %s", fp.Primary)
	}
	if !fp.Matches(fp.ShortDigest) {
		t.Errorf("expected fp to match its short digest: %s", fp.ShortDigest)
	}
	if !fp.Matches(fp.CanonicalDigest) {
		t.Errorf("expected fp to match its canonical digest: %s", fp.CanonicalDigest)
	}
}

func TestAutoDetectResolver(t *testing.T) {
	fp, err := AutoDetectFingerprint()
	if err != nil {
		t.Fatalf("AutoDetectFingerprint failed: %v", err)
	}
	if fp.Primary == "" {
		t.Error("expected non-empty primary fingerprint")
	}
}
