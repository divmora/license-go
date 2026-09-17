package resolvers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// AutoDetectResolver automatically probes the runtime environment and delegates to the appropriate resolver.
type AutoDetectResolver struct {
	ec2Resolver    *AWSEC2Resolver
	lambdaResolver *AWSLambdaResolver
	k8sResolver    *KubernetesResolver
	genResolver    *GenericContainerResolver
	hostResolver   *HostResolver
}

// NewAutoDetectResolver creates a new AutoDetectResolver.
func NewAutoDetectResolver() *AutoDetectResolver {
	return &AutoDetectResolver{
		ec2Resolver:    NewAWSEC2Resolver(),
		lambdaResolver: NewAWSLambdaResolver(),
		k8sResolver:    NewKubernetesResolver(),
		genResolver:    NewGenericContainerResolver(),
		hostResolver:   NewHostResolver(),
	}
}

// Name returns "auto-detect".
func (r *AutoDetectResolver) Name() string {
	return "auto-detect"
}

// Platform returns PlatformGeneric as a default placeholder until resolved.
func (r *AutoDetectResolver) Platform() Platform {
	return PlatformGeneric
}

// DetectEnvironment inspects runtime markers to determine the current execution platform.
func DetectEnvironment() Platform {
	// 1. AWS Lambda
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		return PlatformAWSLambda
	}

	// 2. Kubernetes
	if _, err := os.Stat(defaultK8sServiceAcctDir); err == nil {
		return PlatformKubernetes
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return PlatformKubernetes
	}

	// 3. AWS EC2 (quick IMDS probe)
	if isLikelyAWSEC2() {
		return PlatformAWSEC2
	}

	// 4. Container (Docker/Podman/.dockerenv)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return PlatformGeneric
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return PlatformGeneric
	}

	// 5. Bare-metal / standard VM host
	return PlatformHost
}

func isLikelyAWSEC2() bool {
	// Fast check: DMI product UUID on EC2 often starts with "ec2" or "EC2"
	if uuid := getLinuxProductUUID(); uuid != "" {
		if strings.HasPrefix(strings.ToLower(uuid), "ec2") {
			return true
		}
	}
	// Attempt quick probe to 169.254.169.254 with 100ms timeout
	client := &http.Client{Timeout: 100 * time.Millisecond}
	req, err := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "10")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	return false
}

// Resolve automatically detects the environment and resolves the machine fingerprint.
func (r *AutoDetectResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	platform := DetectEnvironment()

	switch platform {
	case PlatformAWSLambda:
		if fp, err := r.lambdaResolver.Resolve(ctx); err == nil {
			return fp, nil
		}
	case PlatformKubernetes:
		if fp, err := r.k8sResolver.Resolve(ctx); err == nil {
			return fp, nil
		}
	case PlatformAWSEC2:
		if fp, err := r.ec2Resolver.Resolve(ctx); err == nil {
			return fp, nil
		}
	case PlatformGeneric:
		if fp, err := r.genResolver.Resolve(ctx); err == nil {
			return fp, nil
		}
	}

	// Fallback to host resolver
	fp, err := r.hostResolver.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("auto-detect failed all platform resolvers: %w", err)
	}
	return fp, nil
}

// AutoDetectFingerprint resolves the machine identity automatically based on detected environment.
func AutoDetectFingerprint() (*MachineFingerprint, error) {
	return NewAutoDetectResolver().Resolve(context.Background())
}

// AutoDetectFingerprintWithContext resolves the machine identity automatically with context.
func AutoDetectFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewAutoDetectResolver().Resolve(ctx)
}
