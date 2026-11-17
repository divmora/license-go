package resolvers

import (
	"context"
	"fmt"
	"os"
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

var k8sServiceAccountDir = defaultK8sServiceAcctDir

func isKubernetesRuntime() bool {
	return hasValidServiceAccountDir(k8sServiceAccountDir)
}

// DetectEnvironment inspects runtime markers to determine the current execution platform.
func DetectEnvironment() Platform {
	// 1. AWS Lambda
	if isLambdaRuntime() {
		return PlatformAWSLambda
	}

	// 2. Kubernetes
	if isKubernetesRuntime() {
		return PlatformKubernetes
	}

	// 3. AWS EC2 (DMI signals, then IMDS probe; cached for the process lifetime)
	if IsLikelyAWSEC2() {
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
