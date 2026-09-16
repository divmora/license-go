package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAWSEC2Resolver_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			if r.Method != http.MethodPut {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "60" {
				http.Error(w, "missing or invalid ttl header", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("mock-aws-session-token"))
		case "/latest/dynamic/instance-identity/document":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("X-aws-ec2-metadata-token") != "mock-aws-session-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			doc := ec2IdentityDocument{
				InstanceID:       "i-0123456789abcdef0",
				AccountID:        "123456789012",
				Region:           "us-east-1",
				AvailabilityZone: "us-east-1a",
				InstanceType:     "m5.large",
				Architecture:     "x86_64",
				ImageID:          "ami-0987654321fedcba0",
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
	)

	if resolver.Name() != "aws-ec2-imds" {
		t.Errorf("expected name 'aws-ec2-imds', got %q", resolver.Name())
	}
	if resolver.Platform() != PlatformAWSEC2 {
		t.Errorf("expected platform %v, got %v", PlatformAWSEC2, resolver.Platform())
	}

	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("AWSEC2Resolver.Resolve() error = %v", err)
	}
	if fp == nil {
		t.Fatal("expected non-nil MachineFingerprint")
	}

	if fp.Platform != PlatformAWSEC2 {
		t.Errorf("expected platform %v, got %v", PlatformAWSEC2, fp.Platform)
	}
	if !strings.HasPrefix(fp.Primary, "fp:aws:") {
		t.Errorf("expected primary prefix 'fp:aws:', got %q", fp.Primary)
	}
	if fp.Components["instance_id"] != "i-0123456789abcdef0" {
		t.Errorf("expected instance_id 'i-0123456789abcdef0', got %q", fp.Components["instance_id"])
	}
	if fp.Components["account_id"] != "123456789012" {
		t.Errorf("expected account_id '123456789012', got %q", fp.Components["account_id"])
	}
	if fp.Components["region"] != "us-east-1" {
		t.Errorf("expected region 'us-east-1', got %q", fp.Components["region"])
	}

	// Test flexible matching
	if !fp.Matches("i-0123456789abcdef0") {
		t.Error("expected match against raw instance_id")
	}
	if !fp.Matches(fp.Primary) {
		t.Error("expected match against primary")
	}
	if !fp.Matches("fp:aws:" + fp.ShortDigest) {
		t.Error("expected match against fp:aws:<shortDigest>")
	}
}

func TestAWSEC2Resolver_FailureModes(t *testing.T) {
	t.Run("404 token endpoint", func(t *testing.T) {
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
	})

	t.Run("empty token", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		resolver := NewAWSEC2Resolver(
			WithAWSEC2BaseURL(ts.URL),
			WithAWSEC2Timeout(500*time.Millisecond),
		)
		_, err := resolver.Resolve(context.Background())
		if err == nil {
			t.Fatal("expected error on empty token, got nil")
		}
	})

	t.Run("invalid json identity document", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/api/token" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("mock-token"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		}))
		defer ts.Close()

		resolver := NewAWSEC2Resolver(
			WithAWSEC2BaseURL(ts.URL),
			WithAWSEC2Timeout(500*time.Millisecond),
		)
		_, err := resolver.Resolve(context.Background())
		if err == nil {
			t.Fatal("expected error on invalid json, got nil")
		}
	})
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
		if r.Header.Get("Authorization") != "Bearer mock-k8s-jwt-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
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
	if fp == nil {
		t.Fatal("expected non-nil MachineFingerprint")
	}

	if fp.Platform != PlatformKubernetes {
		t.Errorf("expected platform %v, got %v", PlatformKubernetes, fp.Platform)
	}
	if !strings.HasPrefix(fp.Primary, "fp:k8s:") {
		t.Errorf("expected primary prefix 'fp:k8s:', got %q", fp.Primary)
	}
	if fp.Components["cluster_uid"] != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("expected cluster_uid 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', got %q", fp.Components["cluster_uid"])
	}
	if fp.Components["namespace"] != "prod-fleet" {
		t.Errorf("expected namespace 'prod-fleet', got %q", fp.Components["namespace"])
	}

	// Test flexible matching
	if !fp.Matches("a1b2c3d4-e5f6-7890-abcd-ef1234567890") {
		t.Error("expected match against raw cluster_uid")
	}
	if !fp.Matches(fp.Primary) {
		t.Error("expected match against primary")
	}
	if !fp.Matches("fp:k8s:" + fp.ShortDigest) {
		t.Error("expected match against fp:k8s:<shortDigest>")
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
	if !fp.Matches("cluster-eu-west-1-alpha") {
		t.Error("expected match against explicit cluster ID")
	}
}

func TestKubernetesResolver_NotInK8s(t *testing.T) {
	tmpDir := t.TempDir() // empty dir, no serviceaccount
	resolver := NewKubernetesResolver(
		WithKubernetesServiceAccountDir(filepath.Join(tmpDir, "nonexistent")),
	)
	_, err := resolver.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error when outside kubernetes, got nil")
	}
}

func TestCompositeResolver(t *testing.T) {
	// Mock resolvers
	k8sFp := &MachineFingerprint{
		Primary:  "fp:k8s:1111222233334444",
		Platform: PlatformKubernetes,
	}
	awsFp := &MachineFingerprint{
		Primary:  "fp:aws:5555666677778888",
		Platform: PlatformAWSEC2,
	}

	failResolver := &mockResolver{
		name:     "failing",
		platform: PlatformGeneric,
		err:      os.ErrNotExist,
	}
	k8sMock := &mockResolver{
		name:     "k8s-mock",
		platform: PlatformKubernetes,
		fp:       k8sFp,
	}
	awsMock := &mockResolver{
		name:     "aws-mock",
		platform: PlatformAWSEC2,
		fp:       awsFp,
	}

	t.Run("first resolver succeeds", func(t *testing.T) {
		comp := NewCompositeResolver(k8sMock, awsMock)
		fp, err := comp.Resolve(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fp.Primary != k8sFp.Primary {
			t.Errorf("expected k8s fingerprint, got %q", fp.Primary)
		}
	})

	t.Run("first fails, second succeeds", func(t *testing.T) {
		comp := NewCompositeResolver(failResolver, awsMock)
		fp, err := comp.Resolve(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fp.Primary != awsFp.Primary {
			t.Errorf("expected aws fingerprint, got %q", fp.Primary)
		}
	})

	t.Run("all fail", func(t *testing.T) {
		comp := NewCompositeResolver(failResolver)
		_, err := comp.Resolve(context.Background())
		if err == nil {
			t.Fatal("expected error when all resolvers fail, got nil")
		}
	})

	t.Run("empty resolvers list", func(t *testing.T) {
		comp := NewCompositeResolver()
		_, err := comp.Resolve(context.Background())
		if err == nil {
			t.Fatal("expected error with empty resolvers, got nil")
		}
	})
}

func TestResolveDefaultFingerprint(t *testing.T) {
	// On this test machine (macOS/host), K8s and AWS IMDS should fail/skip and fallback to Host
	fp, err := ResolveDefaultFingerprint()
	if err != nil {
		t.Fatalf("ResolveDefaultFingerprint() error = %v", err)
	}
	if fp == nil {
		t.Fatal("expected non-nil MachineFingerprint")
	}
	if fp.Platform != PlatformHost {
		t.Logf("Platform detected: %v (expected host on local test runner)", fp.Platform)
	}
	if fp.CanonicalDigest == "" || fp.ShortDigest == "" {
		t.Error("expected non-empty digests")
	}
}

type mockResolver struct {
	name     string
	platform Platform
	fp       *MachineFingerprint
	err      error
}

func (m *mockResolver) Name() string {
	return m.name
}

func (m *mockResolver) Platform() Platform {
	return m.platform
}

func (m *mockResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.fp, nil
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
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}

	if fp.Platform != PlatformAWSLambda {
		t.Errorf("expected platform %v, got %v", PlatformAWSLambda, fp.Platform)
	}
	if !strings.HasPrefix(fp.Primary, "fp:lambda:") {
		t.Errorf("expected primary prefix 'fp:lambda:', got %q", fp.Primary)
	}
	if fp.Components["function_name"] != "otel-aws-log-processor" {
		t.Errorf("expected function_name 'otel-aws-log-processor', got %q", fp.Components["function_name"])
	}
	if fp.Components["region"] != "us-west-2" {
		t.Errorf("expected region 'us-west-2', got %q", fp.Components["region"])
	}
	if fp.Components["account_id"] != "987654321098" {
		t.Errorf("expected account_id '987654321098', got %q", fp.Components["account_id"])
	}
	if fp.Components["function_arn"] != "arn:aws:lambda:us-west-2:987654321098:function:otel-aws-log-processor" {
		t.Errorf("expected function_arn, got %q", fp.Components["function_arn"])
	}
	if fp.Components["memory_size_mb"] != "1024" {
		t.Errorf("expected memory_size_mb '1024', got %q", fp.Components["memory_size_mb"])
	}
	if fp.Components["runtime"] != "provided.al2023" {
		t.Errorf("expected runtime 'provided.al2023', got %q", fp.Components["runtime"])
	}

	// Determinism
	fp2, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.Primary != fp2.Primary || fp.CanonicalDigest != fp2.CanonicalDigest {
		t.Errorf("non-deterministic resolution: %q vs %q", fp.Primary, fp2.Primary)
	}
}

func TestAWSLambdaResolver_SuccessWithEnv(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "my-env-lambda")
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
	if fp.Components["region"] != "eu-central-1" {
		t.Errorf("expected region 'eu-central-1', got %q", fp.Components["region"])
	}
	if fp.Components["account_id"] != "112233445566" {
		t.Errorf("expected account_id '112233445566', got %q", fp.Components["account_id"])
	}
	if fp.Components["memory_size_mb"] != "512" {
		t.Errorf("expected memory '512', got %q", fp.Components["memory_size_mb"])
	}
}

func TestAWSLambdaResolver_ARNParsing(t *testing.T) {
	// Only ARN set in env; region, account_id, and function_name should be extracted automatically
	t.Setenv("LAMBDA_TASK_ROOT", "/var/task")
	t.Setenv("AWS_LAMBDA_FUNCTION_ARN", "arn:aws:lambda:ap-southeast-1:555666777888:function:auto-extracted-func:$LATEST")
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_ACCOUNT_ID", "")

	resolver := NewAWSLambdaResolver()
	fp, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fp.Components["function_name"] != "auto-extracted-func" {
		t.Errorf("expected extracted function_name 'auto-extracted-func', got %q", fp.Components["function_name"])
	}
	if fp.Components["region"] != "ap-southeast-1" {
		t.Errorf("expected extracted region 'ap-southeast-1', got %q", fp.Components["region"])
	}
	if fp.Components["account_id"] != "555666777888" {
		t.Errorf("expected extracted account_id '555666777888', got %q", fp.Components["account_id"])
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
	if !strings.Contains(err.Error(), "not running inside an aws lambda environment") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAWSLambdaResolver_ConvenienceFunctions(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "convenience-test-func")
	t.Setenv("AWS_REGION", "us-east-2")

	fp, err := ResolveAWSLambdaFingerprint()
	if err != nil {
		t.Fatalf("ResolveAWSLambdaFingerprint error = %v", err)
	}
	if fp.Platform != PlatformAWSLambda {
		t.Errorf("expected PlatformAWSLambda, got %v", fp.Platform)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fp2, err := ResolveAWSLambdaFingerprintWithContext(ctx)
	if err != nil {
		t.Fatalf("ResolveAWSLambdaFingerprintWithContext error = %v", err)
	}
	if fp2.Primary != fp.Primary {
		t.Errorf("expected matching primary IDs: %q vs %q", fp.Primary, fp2.Primary)
	}
}

func TestCompositeResolver_LambdaPriority(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "priority-lambda-func")
	t.Setenv("AWS_REGION", "us-east-1")

	comp := NewDefaultCompositeResolver()
	fp, err := comp.Resolve(context.Background())
	if err != nil {
		t.Fatalf("expected default composite to resolve in Lambda environment, got: %v", err)
	}
	if fp.Platform != PlatformAWSLambda {
		t.Errorf("expected PlatformAWSLambda to take priority over other platforms, got %v", fp.Platform)
	}
	if fp.Components["function_name"] != "priority-lambda-func" {
		t.Errorf("expected function_name 'priority-lambda-func', got %q", fp.Components["function_name"])
	}
}
