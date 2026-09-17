package license

import (
	"context"

	"github.com/divmora/license-go/internal/resolvers"
)

// Platform categorizes the execution environment where a machine fingerprint was evaluated.
type Platform = resolvers.Platform

const (
	// PlatformHost represents a physical machine, bare-metal server, or standard virtual machine.
	PlatformHost Platform = resolvers.PlatformHost

	// PlatformAWSEC2 represents an Amazon Web Services EC2 virtual machine instance.
	PlatformAWSEC2 Platform = resolvers.PlatformAWSEC2

	// PlatformAWSLambda represents an Amazon Web Services Lambda serverless execution environment.
	PlatformAWSLambda Platform = resolvers.PlatformAWSLambda

	// PlatformKubernetes represents a container running within a Kubernetes cluster.
	PlatformKubernetes Platform = resolvers.PlatformKubernetes

	// PlatformGeneric represents a generic or fallback containerized environment.
	PlatformGeneric Platform = resolvers.PlatformGeneric
)

// MachineFingerprint encapsulates deterministic hardware and cloud identity attributes.
type MachineFingerprint = resolvers.MachineFingerprint

// FingerprintResolver defines the interface for resolving machine or cluster identity.
type FingerprintResolver = resolvers.FingerprintResolver

// HostResolver resolves machine identity by inspecting OS-level hardware and system identifiers.
type HostResolver = resolvers.HostResolver

// NewHostResolver constructs a new HostResolver.
func NewHostResolver() *HostResolver {
	return resolvers.NewHostResolver()
}

// ResolveHostFingerprint resolves the local host machine identity with default context.
func ResolveHostFingerprint() (*MachineFingerprint, error) {
	return resolvers.ResolveHostFingerprint()
}

// ResolveHostFingerprintWithContext resolves the local host machine identity with the provided context.
func ResolveHostFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.ResolveHostFingerprintWithContext(ctx)
}

func computeCanonicalDigest(platform Platform, components map[string]string) (string, string) {
	return resolvers.ComputeCanonicalDigest(platform, components)
}
