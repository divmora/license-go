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
	resolver := NewAutoDetectResolver()
	if resolver.Name() != "auto-detect" {
		t.Errorf("expected name 'auto-detect', got %s", resolver.Name())
	}
	if resolver.Platform() != PlatformGeneric {
		t.Errorf("expected platform 'generic', got %s", resolver.Platform())
	}

	fp, err := AutoDetectFingerprint()
	if err != nil {
		t.Fatalf("AutoDetectFingerprint failed: %v", err)
	}
	if fp.Primary == "" {
		t.Error("expected non-empty primary fingerprint")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fp2, err := AutoDetectFingerprintWithContext(ctx)
	if err != nil {
		t.Fatalf("AutoDetectFingerprintWithContext failed: %v", err)
	}
	if fp2.Primary != fp.Primary {
		t.Errorf("primary mismatch: %s vs %s", fp2.Primary, fp.Primary)
	}
}

func TestGenericContainerResolver(t *testing.T) {
	resolver := NewGenericContainerResolver()
	if resolver.Name() != "generic-container" {
		t.Errorf("expected name 'generic-container', got %s", resolver.Name())
	}
	if resolver.Platform() != PlatformGeneric {
		t.Errorf("expected platform 'generic', got %s", resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("GenericContainerResolver.Resolve failed: %v", err)
	}
	if fp.Platform != PlatformGeneric {
		t.Errorf("expected PlatformGeneric, got %s", fp.Platform)
	}
	if fp.Primary == "" {
		t.Error("expected non-empty Primary")
	}
	if !fp.Matches(fp.Primary) {
		t.Errorf("expected fp to match its primary: %s", fp.Primary)
	}

	// Test convenience functions
	fp2, err := ResolveGenericContainerFingerprint()
	if err != nil {
		t.Fatalf("ResolveGenericContainerFingerprint failed: %v", err)
	}
	if fp2.Primary == "" {
		t.Error("expected non-empty Primary from convenience function")
	}

	fp3, err := ResolveGenericContainerFingerprintWithContext(context.Background())
	if err != nil {
		t.Fatalf("ResolveGenericContainerFingerprintWithContext failed: %v", err)
	}
	if fp3.Primary == "" {
		t.Error("expected non-empty Primary from convenience with context")
	}
}

func TestDetectEnvironment(t *testing.T) {
	t.Run("detects lambda", func(t *testing.T) {
		t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "my-lambda-fn")
		if env := DetectEnvironment(); env != PlatformAWSLambda {
			t.Errorf("expected PlatformAWSLambda, got %s", env)
		}
	})

	t.Run("detects host", func(t *testing.T) {
		t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		if env := DetectEnvironment(); env != PlatformHost {
			t.Logf("Detected environment: %s", env)
		}
	})
}

func TestDefaultCompositeResolver(t *testing.T) {
	resolver := NewDefaultCompositeResolver()
	if resolver.Name() != "composite" {
		t.Errorf("expected name 'composite', got %s", resolver.Name())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("DefaultCompositeResolver.Resolve failed: %v", err)
	}
	if fp.Primary == "" {
		t.Error("expected non-empty primary fingerprint")
	}
}
