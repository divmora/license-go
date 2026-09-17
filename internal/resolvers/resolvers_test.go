package resolvers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	fp2, err := ResolveHostFingerprint()
	if err != nil || fp2.Primary == "" {
		t.Errorf("ResolveHostFingerprint failed: %v", err)
	}
	fp3, err := ResolveHostFingerprintWithContext(context.Background())
	if err != nil || fp3.Primary == "" {
		t.Errorf("ResolveHostFingerprintWithContext failed: %v", err)
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
		t.Setenv("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
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
	if resolver.Platform() != PlatformGeneric {
		t.Errorf("expected platform 'generic', got %s", resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("DefaultCompositeResolver.Resolve failed: %v", err)
	}
	if fp.Primary == "" {
		t.Error("expected non-empty primary fingerprint")
	}

	fp2, err := ResolveDefaultFingerprint()
	if err != nil || fp2.Primary == "" {
		t.Errorf("ResolveDefaultFingerprint failed: %v", err)
	}
	fp3, err := ResolveDefaultFingerprintWithContext(context.Background())
	if err != nil || fp3.Primary == "" {
		t.Errorf("ResolveDefaultFingerprintWithContext failed: %v", err)
	}
}

func TestAWSEC2Resolver_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			if r.Method != http.MethodPut {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("mock-aws-session-token"))
		case "/latest/dynamic/instance-identity/document":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			doc := ec2IdentityDocument{
				InstanceID:   "i-0123456789abcdef0",
				AccountID:    "123456789012",
				Region:       "us-east-1",
				InstanceType: "m5.large",
				ImageID:      "ami-12345",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	resolver := NewAWSEC2Resolver(
		WithAWSEC2BaseURL(ts.URL),
		WithAWSEC2Timeout(2*time.Second),
		WithAWSEC2HTTPClient(ts.Client()),
	)

	if resolver.Name() != "aws-ec2-imds" {
		t.Errorf("expected name 'aws-ec2-imds', got %q", resolver.Name())
	}
	if resolver.Platform() != PlatformAWSEC2 {
		t.Errorf("expected platform %v, got %v", PlatformAWSEC2, resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("AWSEC2Resolver.Resolve failed: %v", err)
	}
	if !strings.HasPrefix(fp.Primary, "fp:aws:") {
		t.Errorf("expected primary prefix 'fp:aws:', got %q", fp.Primary)
	}
	if fp.Components["instance_id"] != "i-0123456789abcdef0" {
		t.Errorf("expected instance_id 'i-0123456789abcdef0', got %q", fp.Components["instance_id"])
	}
}

func TestAWSEC2Resolver_FailureModes(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	resolver := NewAWSEC2Resolver(
		WithAWSEC2BaseURL(ts.URL),
		WithAWSEC2Timeout(500*time.Millisecond),
	)
	_, err := resolver.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error on 404 token endpoint, got nil")
	}
}

func TestKubernetesResolver_InClusterWithAPI(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "namespace"), []byte("prod-fleet"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "token"), []byte("mock-k8s-jwt-token"), 0600); err != nil {
		t.Fatal(err)
	}

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/kube-system" {
			http.NotFound(w, r)
			return
		}
		resp := k8sNamespaceMetadata{}
		resp.Metadata.UID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		resp.Metadata.Name = "kube-system"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer apiServer.Close()

	resolver := NewKubernetesResolver(
		WithKubernetesServiceAccountDir(tmpDir),
		WithKubernetesAPIBaseURL(apiServer.URL),
		WithKubernetesHTTPClient(apiServer.Client()),
		WithKubernetesTimeout(2*time.Second),
	)

	if resolver.Name() != "kubernetes-cluster" {
		t.Errorf("expected name 'kubernetes-cluster', got %q", resolver.Name())
	}
	if resolver.Platform() != PlatformKubernetes {
		t.Errorf("expected platform %v, got %v", PlatformKubernetes, resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("KubernetesResolver.Resolve() error = %v", err)
	}
	if !strings.HasPrefix(fp.Primary, "fp:k8s:") {
		t.Errorf("expected primary prefix 'fp:k8s:', got %q", fp.Primary)
	}
	if fp.Components["cluster_uid"] != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("expected cluster_uid match, got %q", fp.Components["cluster_uid"])
	}
}

func TestKubernetesResolver_ExplicitClusterID(t *testing.T) {
	resolver := NewKubernetesResolver(
		WithKubernetesClusterID("cluster-eu-west-1-alpha"),
	)

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("KubernetesResolver with explicit cluster ID failed: %v", err)
	}
	if fp.Components["cluster_uid"] != "cluster-eu-west-1-alpha" {
		t.Errorf("expected cluster_uid 'cluster-eu-west-1-alpha', got %q", fp.Components["cluster_uid"])
	}
}

func TestKubernetesResolver_NotInK8s(t *testing.T) {
	tmpDir := t.TempDir()
	resolver := NewKubernetesResolver(
		WithKubernetesServiceAccountDir(filepath.Join(tmpDir, "nonexistent")),
	)
	_, err := resolver.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error when outside kubernetes, got nil")
	}
}

func TestKubernetesResolver_RBACRestricted_UsesClusterCA(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "namespace"), []byte("production"), 0600)
	jwtToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL29pZGMuZWtzLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tL2lkL0NMVVNURVIxMjMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cHJvZHVjdGlvbjpkZWZhdWx0In0.mock-signature"
	_ = os.WriteFile(filepath.Join(tmpDir, "token"), []byte(jwtToken), 0600)

	caCertContent := []byte("-----BEGIN CERTIFICATE-----\nMIICMockClusterRootCertificateAuthorityData1234567890==\n-----END CERTIFICATE-----\n")
	_ = os.WriteFile(filepath.Join(tmpDir, "ca.crt"), caCertContent, 0600)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer apiServer.Close()

	resolver := NewKubernetesResolver(
		WithKubernetesServiceAccountDir(tmpDir),
		WithKubernetesAPIBaseURL(apiServer.URL),
	)

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("KubernetesResolver.Resolve failed: %v", err)
	}

	expectedCAHashSum := sha256.Sum256(caCertContent)
	expectedCAHash := hex.EncodeToString(expectedCAHashSum[:])
	if fp.Components["cluster_ca_hash"] != expectedCAHash {
		t.Errorf("expected cluster_ca_hash %q, got %q", expectedCAHash, fp.Components["cluster_ca_hash"])
	}
}

func TestAWSLambdaResolver_SuccessWithOptions(t *testing.T) {
	resolver := NewAWSLambdaResolver(
		WithAWSLambdaFunctionName("otel-aws-log-processor"),
		WithAWSLambdaRegion("us-west-2"),
		WithAWSLambdaAccountID("987654321098"),
		WithAWSLambdaFunctionARN("arn:aws:lambda:us-west-2:987654321098:function:otel-aws-log-processor"),
		WithAWSLambdaMemorySize("1024"),
		WithAWSLambdaRuntime("provided.al2023"),
	)

	if resolver.Name() != "aws-lambda-env" {
		t.Errorf("expected name 'aws-lambda-env', got %q", resolver.Name())
	}
	if resolver.Platform() != PlatformAWSLambda {
		t.Errorf("expected platform %v, got %v", PlatformAWSLambda, resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(fp.Primary, "fp:lambda:") {
		t.Errorf("expected primary prefix 'fp:lambda:', got %q", fp.Primary)
	}
	if fp.Components["function_name"] != "otel-aws-log-processor" {
		t.Errorf("expected function_name 'otel-aws-log-processor', got %q", fp.Components["function_name"])
	}
}

func TestAWSLambdaResolver_SuccessWithEnv(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "my-env-lambda")
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
	t.Setenv("AWS_REGION", "eu-central-1")
	t.Setenv("AWS_ACCOUNT_ID", "112233445566")
	t.Setenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", "512")
	t.Setenv("AWS_EXECUTION_ENV", "AWS_Lambda_go1.x")

	resolver := NewAWSLambdaResolver()
	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.Components["function_name"] != "my-env-lambda" {
		t.Errorf("expected function_name 'my-env-lambda', got %q", fp.Components["function_name"])
	}

	fp2, err := ResolveAWSLambdaFingerprint()
	if err != nil || fp2.Primary == "" {
		t.Errorf("ResolveAWSLambdaFingerprint failed: %v", err)
	}
	fp3, err := ResolveAWSLambdaFingerprintWithContext(context.Background())
	if err != nil || fp3.Primary == "" {
		t.Errorf("ResolveAWSLambdaFingerprintWithContext failed: %v", err)
	}
}

func TestAWSLambdaResolver_OutsideLambda(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	t.Setenv("LAMBDA_TASK_ROOT", "")
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "")

	resolver := NewAWSLambdaResolver()
	_, err := resolver.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error when outside lambda, got nil")
	}
}

func TestMachineFingerprint_FormatSummary(t *testing.T) {
	fp := &MachineFingerprint{
		Primary:         "fp:test:12345",
		Platform:        PlatformHost,
		CanonicalDigest: "abcdef123456",
		ShortDigest:     "12345",
		Components: map[string]string{
			"os":   "darwin",
			"arch": "arm64",
		},
		ResolvedAt: time.Now().UTC(),
	}
	summary := fp.FormatSummary()
	if summary != "fp:test:12345 (host, darwin/arm64)" {
		t.Errorf("unexpected FormatSummary output: %s", summary)
	}

	var nilFp *MachineFingerprint
	if nilFp.FormatSummary() != "No machine fingerprint" {
		t.Errorf("expected 'No machine fingerprint', got %s", nilFp.FormatSummary())
	}
}

func TestResolvers_EC2AndK8sWrappers(t *testing.T) {
	// EC2 wrappers outside EC2 return error
	_, err := ResolveAWSEC2Fingerprint()
	if err == nil {
		t.Log("ResolveAWSEC2Fingerprint succeeded on EC2")
	}
	_, err = ResolveAWSEC2FingerprintWithContext(context.Background())
	if err == nil {
		t.Log("ResolveAWSEC2FingerprintWithContext succeeded on EC2")
	}

	// K8s wrappers outside K8s return error
	_, err = ResolveKubernetesFingerprint()
	if err == nil {
		t.Log("ResolveKubernetesFingerprint succeeded in cluster")
	}
	_, err = ResolveKubernetesFingerprintWithContext(context.Background())
	if err == nil {
		t.Log("ResolveKubernetesFingerprintWithContext succeeded in cluster")
	}

	// WithAllowInsecureNamespaceClusterID option constructor
	optInsecure := WithAllowInsecureNamespaceClusterID(true)
	if optInsecure == nil {
		t.Error("WithAllowInsecureNamespaceClusterID returned nil")
	}
	k8sWithInsecure := NewKubernetesResolver(optInsecure)
	if !k8sWithInsecure.allowInsecureNamespaceClusterID {
		t.Error("expected allowInsecureNamespaceClusterID to be true")
	}
}

func TestMachineFingerprint_Matches_Exhaustive(t *testing.T) {
	fp := &MachineFingerprint{
		Primary:         "fp:aws:abcd1234ef567890",
		Platform:        PlatformAWSEC2,
		CanonicalDigest: "abcdef1234567890abcdef1234567890",
		ShortDigest:     "abcd1234ef567890",
		Components: map[string]string{
			"instance_id":     "i-0123456789abcdef0",
			"account_id":      "123456789012",
			"cluster_uid":     "cluster-prod-1",
			"cluster_ca_hash": "ca:beef12345678",
		},
	}

	// Nil receiver
	var nilFp *MachineFingerprint
	if nilFp.Matches("any") {
		t.Error("nil fingerprint should not match")
	}

	// Empty target
	if fp.Matches("") {
		t.Error("empty target should not match")
	}

	// Primary match (with and without fp: prefix, case insensitive)
	if !fp.Matches("fp:aws:abcd1234ef567890") {
		t.Error("expected match against full primary")
	}
	if !fp.Matches("FP:AWS:ABCD1234EF567890") {
		t.Error("expected case-insensitive match against primary")
	}
	if !fp.Matches("abcd1234ef567890") {
		t.Error("expected match against short digest")
	}
	if !fp.Matches("fp:aws:" + fp.ShortDigest) {
		t.Error("expected match against platform:short digest")
	}
	if !fp.Matches(fp.CanonicalDigest) {
		t.Error("expected match against canonical digest")
	}

	// Component matches
	if !fp.Matches("i-0123456789abcdef0") {
		t.Error("expected match against instance_id component")
	}
	if !fp.Matches("cluster-prod-1") {
		t.Error("expected match against cluster_uid component")
	}
	if !fp.Matches("beef12345678") {
		t.Error("expected match against cluster_ca_hash component stripped of ca: prefix")
	}

	// Non-matching values
	if fp.Matches("i-99999999999999999") {
		t.Error("unexpected match for wrong instance_id")
	}
	if fp.Matches("fp:k8s:9999999999999999") {
		t.Error("unexpected match for wrong digest with platform prefix")
	}
}

func TestCompositeResolver_Errors(t *testing.T) {
	// Empty composite
	emptyComp := NewCompositeResolver()
	_, err := emptyComp.Resolve(context.Background())
	if err == nil {
		t.Error("expected error for empty CompositeResolver")
	}

	// All resolvers fail
	failingComp := NewCompositeResolver(NewKubernetesResolver(), NewAWSEC2Resolver())
	_, err = failingComp.Resolve(context.Background())
	if err == nil {
		t.Log("resolvers did not fail (environment has k8s or ec2)")
	}
}

func TestAWSLambda_SpoofProtection(t *testing.T) {
	// Attacker sets AWS_LAMBDA_FUNCTION_NAME outside Lambda environment without runtime markers
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "target-function-name")
	t.Setenv("LAMBDA_TASK_ROOT", "")
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCOUNT_ID", "123456789012")

	// 1. AWSLambdaResolver.Resolve must fail closed
	r := NewAWSLambdaResolver()
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("security vulnerability: AWSLambdaResolver.Resolve accepted spoofed environment variables")
	}

	// 2. DetectEnvironment must not detect PlatformAWSLambda
	if env := DetectEnvironment(); env == PlatformAWSLambda {
		t.Fatal("security vulnerability: DetectEnvironment detected PlatformAWSLambda with spoofed env var")
	}

	// 3. NewDefaultCompositeResolver must not return a Lambda fingerprint
	comp := NewDefaultCompositeResolver()
	fp, err := comp.Resolve(context.Background())
	if err != nil {
		t.Fatalf("DefaultCompositeResolver failed: %v", err)
	}
	if fp.Platform == PlatformAWSLambda {
		t.Fatalf("security vulnerability: DefaultCompositeResolver resolved AWS Lambda fingerprint on spoofed environment")
	}
}

func TestAutoDetectResolver_MetadataAndDetection(t *testing.T) {
	r := NewAutoDetectResolver()
	if r.Name() != "auto-detect" {
		t.Errorf("expected name auto-detect, got %s", r.Name())
	}
	if r.Platform() != PlatformGeneric {
		t.Errorf("expected platform PlatformGeneric, got %s", r.Platform())
	}

	// Test AutoDetectFingerprint
	fp, err := AutoDetectFingerprint()
	if err != nil {
		t.Fatalf("AutoDetectFingerprint failed: %v", err)
	}
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}

	// Test Lambda environment detection
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "test-function")
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("_HANDLER", "bootstrap")
	if env := DetectEnvironment(); env != PlatformAWSLambda {
		t.Errorf("expected PlatformAWSLambda, got %s", env)
	}
	fpLambda, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("r.Resolve on lambda failed: %v", err)
	}
	if fpLambda.Platform != PlatformAWSLambda {
		t.Errorf("expected platform AWSLambda, got %s", fpLambda.Platform)
	}

	// Test Kubernetes environment detection and fallback
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if env := DetectEnvironment(); env != PlatformKubernetes {
		t.Errorf("expected PlatformKubernetes, got %s", env)
	}
	fpK8sFallback, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("r.Resolve with K8s env set failed fallback: %v", err)
	}
	if fpK8sFallback == nil {
		t.Fatal("expected non-nil fallback fingerprint")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	// Test GenericContainerResolver methods
	gen := NewGenericContainerResolver()
	if gen.Name() != "generic-container" {
		t.Errorf("expected generic-container, got %s", gen.Name())
	}
	if gen.Platform() != PlatformGeneric {
		t.Errorf("expected PlatformGeneric, got %s", gen.Platform())
	}
	fpGen, err := ResolveGenericContainerFingerprint()
	if err != nil {
		t.Fatalf("ResolveGenericContainerFingerprint failed: %v", err)
	}
	if fpGen.Platform != PlatformGeneric {
		t.Errorf("expected PlatformGeneric, got %s", fpGen.Platform)
	}
}
