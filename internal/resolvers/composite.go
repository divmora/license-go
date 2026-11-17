package resolvers

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// CompositeResolver evaluates multiple resolvers in sequence until one successfully resolves.
type CompositeResolver struct {
	resolvers []FingerprintResolver
	// cached marks the default composite: a successful EC2 result is shared
	// process-wide so every licence check in a process sees the same identity.
	cached bool
}

// NewCompositeResolver creates a CompositeResolver with the specified list of resolvers.
func NewCompositeResolver(resolvers ...FingerprintResolver) *CompositeResolver {
	return &CompositeResolver{
		resolvers: resolvers,
	}
}

// NewDefaultCompositeResolver creates a CompositeResolver with default priority:
// 1. AWS Lambda (if in serverless runtime)
// 2. Kubernetes (if in-cluster)
// 3. AWS EC2 (if running on EC2)
// 4. Host hardware (OS / Bare metal / VM fallback)
//
// The EC2 step only runs when IsLikelyAWSEC2 (cached per process) reports
// true, and it retries transient IMDS failures. A successful EC2 result is
// cached for the process lifetime, so a later IMDS outage cannot switch the
// identity to the host fallback. Lambda, Kubernetes and host results are derived
// from local state on every call and are not cached.
func NewDefaultCompositeResolver() *CompositeResolver {
	c := NewCompositeResolver(
		NewAWSLambdaResolver(),
		NewKubernetesResolver(),
		NewAWSEC2Resolver(withEC2DetectionGate()),
		NewHostResolver(),
	)
	c.cached = true
	return c
}

// Name returns the descriptive name of the resolver.
func (c *CompositeResolver) Name() string {
	return "composite"
}

// Platform returns PlatformGeneric as the aggregate platform.
func (c *CompositeResolver) Platform() Platform {
	return PlatformGeneric
}

// Resolve tries each resolver in sequence, returning the first successful MachineFingerprint.
func (c *CompositeResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	if len(c.resolvers) == 0 {
		return nil, errors.New("composite: no resolvers configured")
	}

	if c.cached && !isLambdaRuntime() && !isKubernetesRuntime() {
		if fp := loadDefaultFingerprint(); fp != nil {
			return fp, nil
		}
	}

	var errs []string
	for _, r := range c.resolvers {
		fp, err := r.Resolve(ctx)
		if err == nil && fp != nil {
			if c.cached && fp.Platform == PlatformAWSEC2 {
				storeDefaultFingerprint(fp)
			}
			return fp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.Name(), err))
		}
	}

	return nil, fmt.Errorf("composite: all resolvers failed (%s)", strings.Join(errs, "; "))
}

// ResolveDefaultFingerprint automatically detects and resolves the machine identity using the default hierarchy.
func ResolveDefaultFingerprint() (*MachineFingerprint, error) {
	return NewDefaultCompositeResolver().Resolve(context.Background())
}

// ResolveDefaultFingerprintWithContext automatically detects and resolves machine identity with context.
func ResolveDefaultFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewDefaultCompositeResolver().Resolve(ctx)
}
