package resolvers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/divmora/license-go/internal/helpers"
)

// Platform categorizes the execution environment where a machine fingerprint was evaluated.
type Platform string

const (
	// PlatformHost represents a physical machine, bare-metal server, or standard virtual machine.
	PlatformHost Platform = "host"

	// PlatformAWSEC2 represents an Amazon Web Services EC2 virtual machine instance.
	PlatformAWSEC2 Platform = "aws-ec2"

	// PlatformAWSLambda represents an Amazon Web Services Lambda serverless execution environment.
	PlatformAWSLambda Platform = "aws-lambda"

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
// Supports exact primary matches, canonical digests, short digests, prefix tolerance,
// and matching against individual strong hardware components.
func (f *MachineFingerprint) Matches(claimed string) bool {
	if f == nil {
		return false
	}
	claimed = strings.TrimSpace(claimed)
	if claimed == "" {
		return false
	}

	// 1. Direct match against Primary, CanonicalDigest, or ShortDigest
	if helpers.ConstantTimeFingerprintMatch(claimed, f.Primary) ||
		helpers.ConstantTimeFingerprintMatch(claimed, f.CanonicalDigest) ||
		helpers.ConstantTimeFingerprintMatch(claimed, f.ShortDigest) {
		return true
	}

	// 2. Prefix-stripped match
	clean := claimed
	for _, prefix := range []string{"fp:host:", "fp:aws:", "fp:lambda:", "fp:k8s:", "fp:generic:", "fp:", "sha256:", "ca:"} {
		if strings.HasPrefix(strings.ToLower(clean), prefix) {
			clean = clean[len(prefix):]
			break
		}
	}
	if helpers.ConstantTimeFingerprintMatch(clean, f.CanonicalDigest) || helpers.ConstantTimeFingerprintMatch(clean, f.ShortDigest) {
		return true
	}

	// 3. Component-level match against stable hardware/workload identifiers
	for k, val := range f.Components {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if k == "system_uuid" || k == "machine_id" || k == "cluster_uid" || k == "instance_id" || k == "function_name" || k == "function_arn" || k == "cluster_ca_hash" {
			if helpers.ConstantTimeFingerprintMatch(claimed, val) || helpers.ConstantTimeFingerprintMatch(clean, val) {
				return true
			}
			if strings.HasPrefix(strings.ToLower(val), "ca:") && helpers.ConstantTimeFingerprintMatch(clean, val[3:]) {
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

// ComputeCanonicalDigest generates deterministic SHA-256 digests for machine components.
func ComputeCanonicalDigest(platform Platform, components map[string]string) (string, string) {
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
	case PlatformAWSLambda:
		if fn := components["function_name"]; fn != "" {
			parts = append(parts, "function:"+fn)
		}
		if acc := components["account_id"]; acc != "" {
			parts = append(parts, "account_id:"+acc)
		}
		if reg := components["region"]; reg != "" {
			parts = append(parts, "region:"+reg)
		}
		if arn := components["function_arn"]; arn != "" {
			parts = append(parts, "arn:"+arn)
		}
	case PlatformKubernetes:
		if uid := components["cluster_uid"]; uid != "" {
			parts = append(parts, "cluster_uid:"+uid)
		}
		if ns := components["namespace"]; ns != "" {
			parts = append(parts, "namespace:"+ns)
		}
		if ca := components["cluster_ca_hash"]; ca != "" {
			parts = append(parts, "ca:"+ca)
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
