package resolvers

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// GenericContainerResolver resolves machine identity for non-K8s containerized workloads
// (e.g. Docker, Podman, containerd, ECS).
type GenericContainerResolver struct{}

// NewGenericContainerResolver creates a new GenericContainerResolver.
func NewGenericContainerResolver() *GenericContainerResolver {
	return &GenericContainerResolver{}
}

// Name returns the descriptive name of the resolver.
func (r *GenericContainerResolver) Name() string {
	return "generic-container"
}

// Platform returns PlatformGeneric.
func (r *GenericContainerResolver) Platform() Platform {
	return PlatformGeneric
}

// Resolve inspects container hostname, cgroup details, and environment to produce a MachineFingerprint.
func (r *GenericContainerResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	components := make(map[string]string)
	components["os"] = runtime.GOOS
	components["arch"] = runtime.GOARCH

	if h, err := os.Hostname(); err == nil && h != "" {
		components["hostname"] = h
	}

	// 1. Inspect container cgroup for container ID
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				cgroupPath := parts[2]
				slashIdx := strings.LastIndex(cgroupPath, "/")
				if slashIdx != -1 {
					possibleID := cgroupPath[slashIdx+1:]
					if len(possibleID) >= 12 {
						components["container_id"] = possibleID
						break
					}
				}
			}
		}
	}

	// 2. Fall back to machine-id if available inside container
	if mid := getLinuxMachineID(); mid != "" {
		components["machine_id"] = mid
	}

	macs := getNetworkMACAddresses()
	if len(macs) > 0 {
		components["mac_addresses"] = strings.Join(macs, ",")
	}

	digest, short := ComputeCanonicalDigest(PlatformGeneric, components)

	return &MachineFingerprint{
		Primary:         fmt.Sprintf("fp:generic:%s", short),
		Platform:        PlatformGeneric,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      components,
		ResolvedAt:      time.Now().UTC(),
	}, nil
}

// ResolveGenericContainerFingerprint resolves the machine identity for a generic container.
func ResolveGenericContainerFingerprint() (*MachineFingerprint, error) {
	return NewGenericContainerResolver().Resolve(context.Background())
}

// ResolveGenericContainerFingerprintWithContext resolves the machine identity for a generic container with context.
func ResolveGenericContainerFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewGenericContainerResolver().Resolve(ctx)
}
