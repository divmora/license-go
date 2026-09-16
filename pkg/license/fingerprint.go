package license

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Platform categorizes the execution environment where a machine fingerprint was evaluated.
type Platform string

const (
	// PlatformHost represents a physical machine, bare-metal server, or standard virtual machine.
	PlatformHost Platform = "host"

	// PlatformAWSEC2 represents an Amazon Web Services EC2 virtual machine instance.
	PlatformAWSEC2 Platform = "aws-ec2"

	// PlatformKubernetes represents a container running within a Kubernetes cluster.
	PlatformKubernetes Platform = "kubernetes"

	// PlatformGeneric represents a generic or fallback containerized environment.
	PlatformGeneric Platform = "generic"
)

// MachineFingerprint encapsulates deterministic hardware and cloud identity attributes.
type MachineFingerprint struct {
	// Primary is the canonical formatted identifier (e.g. "fp:host:a1b2c3d4e5f67890").
	Primary string `json:"primary"`

	// Platform indicates the detected host, cloud, or container environment.
	Platform Platform `json:"platform"`

	// CanonicalDigest is the full 64-character SHA-256 hex digest of the stable machine attributes.
	CanonicalDigest string `json:"canonical_digest"`

	// ShortDigest is the first 16 characters of the CanonicalDigest for concise display.
	ShortDigest string `json:"short_digest"`

	// Components contains individual hardware, OS, network, or cloud properties.
	Components map[string]string `json:"components"`

	// ResolvedAt records the timestamp when the machine identity was resolved.
	ResolvedAt time.Time `json:"resolved_at"`
}

// FingerprintResolver defines the interface for resolving machine or cluster identity.
type FingerprintResolver interface {
	// Name returns the descriptive name of this resolver.
	Name() string

	// Platform returns the environment platform targeted by this resolver.
	Platform() Platform

	// Resolve evaluates and returns the machine fingerprint.
	Resolve(ctx context.Context) (*MachineFingerprint, error)
}

// Matches checks whether the given claimed fingerprint string matches this resolved machine fingerprint.
// It supports exact primary matches, canonical digests, short digests, prefix tolerance (e.g. "fp:host:...", "sha256:..."),
// and matching against individual strong hardware components (such as machine_id or system_uuid).
func (f *MachineFingerprint) Matches(claimed string) bool {
	if f == nil {
		return false
	}
	claimed = strings.TrimSpace(claimed)
	if claimed == "" {
		return false
	}

	// 1. Direct match against Primary, CanonicalDigest, or ShortDigest
	if strings.EqualFold(claimed, f.Primary) ||
		strings.EqualFold(claimed, f.CanonicalDigest) ||
		strings.EqualFold(claimed, f.ShortDigest) {
		return true
	}

	// 2. Prefix-stripped match (strip "fp:host:", "fp:aws:", "fp:k8s:", "fp:", "sha256:")
	clean := claimed
	for _, prefix := range []string{"fp:host:", "fp:aws:", "fp:k8s:", "fp:generic:", "fp:", "sha256:"} {
		if strings.HasPrefix(strings.ToLower(clean), prefix) {
			clean = clean[len(prefix):]
			break
		}
	}
	if strings.EqualFold(clean, f.CanonicalDigest) || strings.EqualFold(clean, f.ShortDigest) {
		return true
	}

	// 3. Component-level match against stable hardware identifiers
	for k, val := range f.Components {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		// Match against system_uuid, machine_id, cluster_uid, instance_id
		if k == "system_uuid" || k == "machine_id" || k == "cluster_uid" || k == "instance_id" {
			if strings.EqualFold(claimed, val) || strings.EqualFold(clean, val) {
				return true
			}
		}
	}

	return false
}

// FormatSummary returns a concise one-line description of the machine fingerprint.
func (f *MachineFingerprint) FormatSummary() string {
	if f == nil {
		return "No machine fingerprint"
	}
	return fmt.Sprintf("%s (%s, %s/%s)", f.Primary, f.Platform, f.Components["os"], f.Components["arch"])
}

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

	digest, short := computeCanonicalDigest(PlatformHost, components)

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

func computeCanonicalDigest(platform Platform, components map[string]string) (string, string) {
	var parts []string
	parts = append(parts, "platform:"+string(platform))
	parts = append(parts, "os:"+components["os"])
	parts = append(parts, "arch:"+components["arch"])

	switch platform {
	case PlatformAWSEC2:
		if id := components["instance_id"]; id != "" {
			parts = append(parts, "instance_id:"+id)
		}
		if acc := components["account_id"]; acc != "" {
			parts = append(parts, "account_id:"+acc)
		}
		if reg := components["region"]; reg != "" {
			parts = append(parts, "region:"+reg)
		}
	case PlatformKubernetes:
		if uid := components["cluster_uid"]; uid != "" {
			parts = append(parts, "cluster_uid:"+uid)
		}
		if ns := components["namespace"]; ns != "" {
			parts = append(parts, "namespace:"+ns)
		}
	default:
		// High-stability hardware identifiers take priority
		if id := components["system_uuid"]; id != "" {
			parts = append(parts, "uuid:"+id)
		} else if id := components["machine_id"]; id != "" {
			parts = append(parts, "machine_id:"+id)
		} else {
			// Fallback to MAC addresses + Hostname
			if macs := components["mac_addresses"]; macs != "" {
				parts = append(parts, "macs:"+macs)
			}
			if h := components["hostname"]; h != "" {
				parts = append(parts, "host:"+h)
			}
		}
	}

	canonicalString := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(canonicalString))
	digest := hex.EncodeToString(h[:])
	short := digest[:16]
	return digest, short
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
