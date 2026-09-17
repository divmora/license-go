package resolvers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// HostResolver resolves machine identity by inspecting OS-level hardware and system identifiers.
type HostResolver struct{}

// NewHostResolver constructs a new HostResolver.
func NewHostResolver() *HostResolver {
	return &HostResolver{}
}

// Name returns the descriptive name of the host resolver.
func (r *HostResolver) Name() string {
	return "host-hardware"
}

// Platform returns PlatformHost.
func (r *HostResolver) Platform() Platform {
	return PlatformHost
}

// Resolve inspects host hardware attributes and returns a deterministic MachineFingerprint.
func (r *HostResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	components := make(map[string]string)
	components["os"] = runtime.GOOS
	components["arch"] = runtime.GOARCH

	if h, err := os.Hostname(); err == nil && h != "" {
		components["hostname"] = h
	}

	// 1. Operating system-specific stable machine identifiers
	switch runtime.GOOS {
	case "linux":
		if mid := getLinuxMachineID(); mid != "" {
			components["machine_id"] = mid
		}
		if uuid := getLinuxProductUUID(); uuid != "" {
			components["system_uuid"] = uuid
		}
	case "darwin":
		if uuid := getDarwinPlatformUUID(ctx); uuid != "" {
			components["system_uuid"] = uuid
			components["machine_id"] = uuid
		}
	}

	// 2. Network hardware MAC addresses
	macs := getNetworkMACAddresses()
	if len(macs) > 0 {
		components["mac_addresses"] = strings.Join(macs, ",")
	}

	digest, short := ComputeCanonicalDigest(PlatformHost, components)

	return &MachineFingerprint{
		Primary:         fmt.Sprintf("fp:%s:%s", PlatformHost, short),
		Platform:        PlatformHost,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      components,
		ResolvedAt:      time.Now().UTC(),
	}, nil
}

// ResolveHostFingerprint resolves the local host machine identity with default context.
func ResolveHostFingerprint() (*MachineFingerprint, error) {
	return NewHostResolver().Resolve(context.Background())
}

// ResolveHostFingerprintWithContext resolves the local host machine identity with the provided context.
func ResolveHostFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewHostResolver().Resolve(ctx)
}

func getNetworkMACAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var macs []string
	seen := make(map[string]bool)
	for _, ifa := range ifaces {
		if ifa.Flags&net.FlagLoopback != 0 {
			continue
		}
		hw := ifa.HardwareAddr.String()
		if hw != "" && !seen[hw] {
			seen[hw] = true
			macs = append(macs, strings.ToLower(hw))
		}
	}
	sort.Strings(macs)
	return macs
}

func getLinuxMachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(path); err == nil {
			s := strings.TrimSpace(string(data))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func getLinuxProductUUID() string {
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			return s
		}
	}
	return ""
}

func getDarwinPlatformUUID(ctx context.Context) string {
	cmdPath := "/usr/sbin/ioreg"
	if p, err := exec.LookPath("ioreg"); err == nil {
		cmdPath = p
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctxTimeout, cmdPath, "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				if val != "" {
					return val
				}
			}
		}
	}
	return ""
}
