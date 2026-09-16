---
name: divmora-license
description: >-
  Use this skill when generating, issuing, verifying, inspecting, or integrating
  Divmora software licenses for products such as gitlab-fleet-governor,
  otel-aws-log-processor, or any Go service under the divmora organization.
---

# Divmora Licensing Skill (`license-go`)

This skill provides step-by-step instructions, code templates, and CLI procedures for issuing and verifying software licenses across all Divmora organization repositories.

---

## 1. Quick Reference

| Attribute | Details |
| :--- | :--- |
| **Go Package** | `github.com/divmora/license-go/pkg/license` |
| **CLI Tool** | `cmd/license-cli` |
| **Algorithm** | Ed25519 Asymmetric Digital Signature |
| **Supported Products** | `gitlab-fleet-governor`, `otel-aws-log-processor`, and any Divmora Go product |
| **Formats** | Armored PEM block (`-----BEGIN DIVMORA LICENSE KEY-----`) or Compact token (`DIV1.<payload>.<sig>`) |

---

## 2. Standard Claims Specification

All Divmora licenses conform to the following schema:

```go
type Customer struct {
    Name  string `json:"name"`
    Email string `json:"email,omitempty"`
    OrgID string `json:"org_id,omitempty"`
}

type Scope struct {
    Environments []string            `json:"environments,omitempty"` // ["production", "staging"]
    Accounts     []string            `json:"accounts,omitempty"`     // AWS Account IDs, tenant IDs
    Regions      []string            `json:"regions,omitempty"`      // Cloud regions ["us-east-1", "eu-west-*"]
    Clusters     []string            `json:"clusters,omitempty"`     // Kubernetes / ECS cluster IDs
    Namespaces   []string            `json:"namespaces,omitempty"`   // GitLab groups/projects ["acme-corp/*"]
    Hosts        []string            `json:"hosts,omitempty"`        // Hostnames, FQDNs, domains ["*.acme.corp"]
    Custom       map[string][]string `json:"custom,omitempty"`       // Product-specific scope dimensions
}

type Claims struct {
    ID              string            `json:"id"`                  // Unique UUID
    Customer        Customer          `json:"customer"`            // Licensee details (name, email, org_id)
    Product         string            `json:"product"`             // e.g., "gitlab-fleet-governor", suite ("divmora-suite"), wildcard ("*"), or multi-product list
    Plan            string            `json:"plan"`                // "community", "starter", "pro", "enterprise", "trial"
    IssuedAt        time.Time         `json:"issued_at"`
    NotBefore       time.Time         `json:"not_before,omitempty"`
    ExpiresAt       time.Time         `json:"expires_at"`          // Zero time = perpetual
    GracePeriodDays int               `json:"grace_period_days,omitempty"` // Buffer days after ExpiresAt
    Features        []string          `json:"features,omitempty"`  // Feature entitlement flags (supports "*", "all", and glob patterns)
    Limits          map[string]int64  `json:"limits,omitempty"`    // -1 = unlimited
    Scope           *Scope            `json:"scope,omitempty"`     // Infrastructure and operational boundary scoping
    Environment     string            `json:"environment,omitempty"` // "production", "staging"
    Fingerprint     string            `json:"fingerprint,omitempty"` // Optional cluster/hardware binding
    MaxVersion      string            `json:"max_version,omitempty"` // Max authorized version (e.g. "1.*", "<=2.5.0")
    AllowedVersions []string          `json:"allowed_versions,omitempty"` // Explicit authorized versions ["1.*", "2.0.*"]
    MaintenanceExpiresAt time.Time    `json:"maintenance_expires_at,omitempty"` // Cutoff for updates in perpetual licenses
    Metadata        map[string]string `json:"metadata,omitempty"`  // Custom key-value pairs
}
```

---

## 3. Standard Workflows

### Workflow A: Generate New Keypair

When setting up licensing keys for an organization or product:

```bash
# Generate private.pem (0600) and public.pem (0644)
license-cli keygen -out-dir ./keys
```

> [!WARNING]
> Keep `private.pem` strictly confidential (store in HashiCorp Vault, AWS Secrets Manager, or CI/CD secret variables). Never commit private keys to version control. Public keys can be safely embedded in binaries or configuration files.

---

### Workflow B: Issue a New License

Issue a signed license for a customer using the private key:

```bash
license-cli issue \
  -private-key /path/to/private.pem \
  -customer "Customer Name" \
  -email "admin@customer.com" \
  -org-id "org_cust_123" \
  -product "<product-name>" \
  -plan enterprise \
  -valid-days 365 \
  -grace-days 14 \
  -features "ha,audit-logs,sso" \
  -limits "max_nodes=50,max_runners=200" \
  -scope-envs "production,staging" \
  -scope-accounts "123456789012" \
  -scope-regions "us-east-1,eu-west-1" \
  -scope-clusters "prod-eks-01" \
  -scope-namespaces "acme-corp/*" \
  -scope-hosts "*.acme.corp" \
  -scope-custom "tier=platinum,gold;datacenter=dc-east,dc-west" \
  -meta "billing_id=inv-9981,contact=admin@customer.com" \
  -out ./license.key \
  -armored
```

For perpetual licenses, pass `-valid-days 0`.

---

### Workflow C: Verify, Inspect, or Format Status via CLI

```bash
# Verify explicit license file or token with standard and custom scope assertions:
license-cli verify \
  -public-key /path/to/public.pem \
  -product "<product-name>" \
  -env "production" \
  -account "123456789012" \
  -region "us-east-1" \
  -cluster "prod-eks-01" \
  -namespace "acme-corp/fleet" \
  -host "srv-01.acme.corp" \
  -custom-scope "tier=platinum,datacenter=dc-east" \
  -fingerprint "<host-fingerprint>" \
  -license ./license.key

# Or verify automatically with zero configuration (resolves license from DIVMORA_LICENSE_KEY/FILE
# and public key from DIVMORA_PUBLIC_KEY / DIVMORA_PUBLIC_KEYS_PEM / /etc/divmora/public.pem):
license-cli verify -product "<product-name>"

# Inspect claims without signature verification (direct or env fallback)
license-cli inspect -license ./license.key
license-cli inspect

# Print standardized visual status card with live capacity/usage overlays:
license-cli status \
  -license ./license.key \
  -usage "max_runners=142,max_nodes=6"

# Or zero-configuration status card:
license-cli status -usage "max_runners=142"
```

---

### Workflow D: Embed Verification into a Go Service

To integrate license checks into a service (e.g., `gitlab-fleet-governor` or `otel-aws-log-processor`):

```go
package main

import (
	"fmt"
	"log"

	license "github.com/divmora/license-go/pkg/license"
)

// Divmora Public Key (embed or read from secret/env)
const defaultPublicKeyBase64 = "o5nIs/8K/bCGz6jRB33Ig1h0ONr37yvVHpddzNnL46U="

func checkLicense() {
	// Auto-resolves public verification key from DIVMORA_PUBLIC_KEYS_PEM,
	// DIVMORA_PUBLIC_KEY, DIVMORA_PUBLIC_KEY_FILE, /etc/divmora/public.pem,
	// or falls back to defaultPublicKeyBase64:
	validator, err := license.NewValidatorWithFallbackKey(
		defaultPublicKeyBase64,
		license.WithProduct("gitlab-fleet-governor"),
	)
	if err != nil {
		log.Fatalf("failed to initialize validator: %v", err)
	}

	// Automatically resolves license from DIVMORA_LICENSE_KEY, DIVMORA_LICENSE_FILE,
	// or /etc/divmora/license.key:
	claims, err := validator.VerifyEnv()
	if err != nil {
		log.Fatalf("Invalid license: %v", err)
	}

	// 1. Check feature flag
	if claims.HasFeature("ha") {
		// enable HA
	}

	// 2. Check quota limit
	if err := claims.CheckLimit("max_runners", 150); err != nil {
		log.Fatalf("License quota exceeded: %v", err)
	}
}
```

---

### Workflow E: Background Daemon Manager (Hot-Reload & Expiry Alerts)

For 24/7 background daemons:

```go
package main

import (
	"context"
	"log"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func startLicenseManager(ctx context.Context, pubKeyPath string) (*license.Manager, error) {
	validator, err := license.NewValidatorFromPEMFile(
		pubKeyPath,
		license.WithProduct("otel-aws-log-processor"),
	)
	if err != nil {
		return nil, err
	}

	// If LicenseFile and LicenseString are omitted, NewManager automatically
	// resolves from DIVMORA_LICENSE_FILE (enabling hot-reload) or DIVMORA_LICENSE_KEY:
	mgr, err := license.NewManager(license.ManagerConfig{
		Validator:         validator,
		CheckInterval:     1 * time.Hour,
		ExpiryWarningDays: 14,
		// Enforcement policy mode: PolicyStrict (default), PolicyDegraded, or PolicyWarnOnly:
		Policy:            license.PolicyDegraded,
		DegradedReadOnly:  true, // Enforces read-only mode (CanMutate() returns ErrDegradedReadOnly)
		FallbackClaims: &license.Claims{
			Product:  "otel-aws-log-processor",
			Plan:     "community",
			Customer: license.Customer{Name: "Community User"},
			Features: []string{"basic-ingest"},
			Limits:   map[string]int64{"max_streams": 10},
		},
		OnExpiringSoon: func(claims *license.Claims, daysRemaining int) {
			log.Printf("[LICENSE] Warning: License expires in %d days", daysRemaining)
		},
		OnGracePeriod: func(claims *license.Claims, graceDaysRemaining int) {
			log.Printf("[LICENSE] Notice: Operating in grace period (%d days remaining)", graceDaysRemaining)
		},
		OnExpired: func(claims *license.Claims) {
			log.Printf("[LICENSE] CRITICAL: License has expired!")
		},
		OnDegraded: func(reason error, claims *license.Claims) {
			log.Printf("[LICENSE] NOTICE: Operating in DEGRADED mode (%v); falling back to %s tier", reason, claims.Plan)
		},
		OnRecovered: func(newClaims *license.Claims) {
			log.Printf("[LICENSE] SUCCESS: Recovered from degraded mode to active license tier: %s", newClaims.Plan)
		},
		OnBSLConverted: func(claims *license.Claims) {
			log.Printf("[LICENSE] CELEBRATION: BSL 1.1 Change Date reached! Converted to Apache 2.0 open-source.")
		},
		OnReloaded: func(newClaims, oldClaims *license.Claims) {
			log.Printf("[LICENSE] Info: License reloaded! New tier: %s", newClaims.Plan)
		},
		OnError: func(err error) {
			log.Printf("[LICENSE] Check error: %v", err)
		},
	})
	if err != nil {
		return nil, err
	}

	mgr.Start(ctx)
	return mgr, nil
}
```

---

### Workflow F: Zero-Downtime Key Rotation & Multi-Key Ring

When rotating signing keys (e.g. 2025 $\rightarrow$ 2026 key), or parsing a multi-key PEM bundle:

```bash
# 1. Inspect all keys inside a trusted PEM bundle:
license-cli keyring ./trusted_keys.pem

# 2. Issue a license with an explicit Key ID:
license-cli issue -private-key ./2026-private.pem -kid "divmora-2026-root" ...
```

In Go applications, load a multi-key PEM bundle or configure fallback keys:

```go
// Auto-resolve KeyRing across env (DIVMORA_PUBLIC_KEYS_PEM, DIVMORA_PUBLIC_KEY)
// and optional fallback keys:
ring, err := license.ResolveKeyRing(primary2026KeyBase64, retiring2025KeyBase64)

// Or programmatic registration with revocation support:
ring := license.NewKeyRing(primary2026Key)
ring.AddKeyWithID("divmora-2025-root", legacy2025Key, license.KeyStatusRetiring)

// If a key was compromised:
ring.Revoke("compromised-key-id") // Any license signed by this key returns ErrKeyRevoked

validator, err := license.NewValidatorWithKeyRing(ring)

// In automated tests, override the active verification key globally:
license.SetVerificationPublicKey(testEphemeralPublicKey)
defer license.ResetVerificationPublicKey()
```

---

### Workflow G: Perpetual Licenses with Version Locking & Maintenance Cutoff

Perpetual licenses run indefinitely (`-valid-days 0`), but are usually locked to a maximum authorized major/minor version or a maintenance cutoff date:

```bash
# Issue perpetual license locked to version 1.* with 365 days of included software updates:
license-cli issue \
  -private-key ./private.pem \
  -customer "Acme Corp" \
  -product "gitlab-fleet-governor" \
  -valid-days 0 \
  -max-version "1.*" \
  -maintenance-days 365 \
  -out ./perpetual.key
```

In the consuming service, configure the current binary version and build timestamp:

```go
var (
	// Injected at build time via ldflags:
	// go build -ldflags "-X main.Version=v1.4.2 -X main.BuildDate=2026-06-15T12:00:00Z"
	Version   = "v1.4.2"
	BuildDate = "2026-06-15T12:00:00Z"
)

func verifyServiceLicense() {
	bTime, _ := time.Parse(time.RFC3339, BuildDate)

	validator, err := license.NewValidatorFromPEMFile(
		"/etc/divmora/public.pem",
		license.WithProduct("gitlab-fleet-governor"),
		license.WithCurrentVersion(Version), // Rejects if Version > claims.MaxVersion (ErrVersionNotEntitled)
		license.WithBuildDate(bTime),        // Rejects if bTime > claims.MaintenanceExpiresAt (ErrMaintenanceExpired)
	)
	...
}
```

---

### Workflow H: BSL 1.1 Automatic Open-Source Conversion & Clock Defense

Products licensed under Business Source License 1.1 convert automatically to open source (`Apache-2.0`) after a set period (default: 3 years from release date). Once converted, commercial license keys are no longer required and standard open-source entitlements are granted automatically.

```go
releaseDate, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")

validator, err := license.NewValidatorFromPEMFile(
	"/etc/divmora/public.pem",
	license.WithProduct("gitlab-fleet-governor"),
	// Configure BSL 1.1 policy (converts to Apache-2.0 after 3 years):
	license.WithBSLPolicy(license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
	}),
	// Defend against forward host clock manipulation by anchoring to authoritative API/NTP time:
	license.WithAuthoritativeTime(serverHttpDate),
)
if err != nil {
	log.Fatalf("failed to create validator: %v", err)
}

// If after Change Date: automatically succeeds with open-source entitlements even without a license!
// If before Change Date: strictly enforces commercial license key and validity period.
claims, err := validator.VerifyEnv()
```

In `license-cli verify`:

```bash
license-cli verify \
  -public-key /path/to/public.pem \
  -product gitlab-fleet-governor \
  -bsl-release-date 2025-01-01 \
  -bsl-years 3 \
  -authoritative-time "2026-06-01T12:00:00Z"
```

---

### Workflow I: Cryptographic Release Attestation & Binary Provenance

To prevent local binary tampering, unauthorized compile-time `-ldflags` manipulation (e.g. forging an ancient release date to claim premature BSL 1.1 Apache 2.0 open-source conversion), or supply-chain compromise:

#### 1. Mint Release Attestation in CI/CD

During official build pipelines, mint an Ed25519 cryptographic release attestation token or armored sidecar (`release.sig`):

```bash
license-cli sign-release \
  -private-key ./keys/private.pem \
  -product "gitlab-fleet-governor" \
  -version "v2.5.0" \
  -git-commit "${CI_COMMIT_SHA}" \
  -binary "./bin/gitlab-fleet-governor" \
  -authority "divmora.com/release" \
  -out "./bin/release.sig" \
  -armored
```

#### 2. Verify Release Binary & Checksum via CLI

```bash
license-cli verify-release \
  -public-key ./keys/public.pem \
  -attestation ./bin/release.sig \
  -product "gitlab-fleet-governor" \
  -version "v2.5.0" \
  -git-commit "${CI_COMMIT_SHA}" \
  -binary "./bin/gitlab-fleet-governor"
```

#### 3. Inspect Release Claims (Unverified)

```bash
license-cli inspect-release -attestation ./bin/release.sig
```

#### 4. Embed Provenance Enforcement in Go Services

```go
validator, err := license.NewValidatorFromPEM(
	publicKeyPEM,
	license.WithProduct("gitlab-fleet-governor"),
	license.WithCurrentVersion(version),
	license.WithCurrentGitCommit(gitCommit),
	license.WithBinaryPath(executablePath),
	license.WithReleaseAttestationFile("/etc/divmora/release.sig"),
	license.WithRequireReleaseAttestation(true), // Enforce fail-closed verification
)
if err != nil {
	log.Fatal(err)
}

result, err := validator.VerifyWithResultEnv()
if err != nil {
	log.Fatalf("Release provenance or license validation failed: %v", err)
}

if result.Provenance != nil && result.Provenance.Attested {
	log.Printf("Certified release: %s %s (signed by: %s)",
		result.Provenance.Claims.Product, result.Provenance.Claims.Version, result.Provenance.VerifiedByKeyID)
}
```

---

### Workflow J: Standardized License Status Formatting (CLI & Go SDK)

For user-facing CLI commands (`<product> license status`, e.g., `gitlab-fleet-governor license status` or `otel-aws-log-processor license status`), render high-impact status card banners with visual badges and capacity/quota utilization tables:

```go
result, err := validator.VerifyWithResultEnv()
if err != nil {
	log.Fatalf("License verification failed: %v", err)
}

// Render status card with live runtime capacity utilization
statusCard := result.FormatStatus(
	license.WithStatusBannerTitle("GITLAB FLEET GOVERNOR - LICENSE STATUS"),
	license.WithStatusUsage(map[string]int64{
		"max_runners": 142,
		"max_nodes":   6,
	}),
)
fmt.Print(statusCard)
```

In standalone CLI:

```bash
# Render visual status card with capacity utilization
license-cli status -license ./license.key -usage "max_runners=142,max_nodes=6"

# Or compact mode (omits box border)
license-cli status -license ./license.key -compact
```

---

### Workflow K: BSL 1.1 Dual-Licensing & Additional Use Grants (AUG)

For products governed under Business Source License 1.1, configure vendor-specific Additional Use Grants (e.g. non-production exemptions and free community tiers) to automatically entitle non-commercial or small-scale deployments without requiring a commercial license token:

```go
policy := license.BSLPolicy{
	ReleaseDate:       releaseDate,
	ChangePeriodYears: 3,
	AdditionalUseGrants: []license.BSLAdditionalUseGrant{
		license.NewNonProductionGrant("Non-Production Exemption"),
		license.NewFreeTierGrant("Community Free Tier", map[string]int64{"max_nodes": 10}, "sso"),
	},
}

validator, err := license.NewValidator(
	pubKey,
	license.WithProduct("gitlab-fleet-governor"),
	license.WithBSLPolicy(policy),
	license.WithEnvironment(os.Getenv("ENV")),
	license.WithCurrentUsage(map[string]int64{"max_nodes": 8}),
)

// Zero-license verification: succeeds under Additional Use Grant or if Change Date has passed
result, err := validator.VerifyWithResultEnv()
if err != nil {
	// If usage exceeds grant bounds, fails with CommercialLicenseRequiredError
	log.Fatalf("Commercial license required: %v", err)
}

if result.BSLGrantAuthorized {
	log.Printf("Running under BSL Additional Use Grant: %s", result.BSLGrantName)
}
```

Evaluate operational context via CLI:

```bash
# Evaluate entitlement for staging or test environments:
license-cli bsl-eval -release-date 2025-01-01 -env staging

# Evaluate production usage against free tier quotas:
license-cli bsl-eval \
  -release-date 2025-01-01 \
  -env production \
  -free-limits "max_nodes=10" \
  -usage "max_nodes=15"
```

---

## 4. Troubleshooting & Sentinel Errors

| Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ErrInvalidSignature` | License payload or signature was altered or signed by an untrusted key | Verify that the license was signed with a trusted private key in the validator's KeyRing. |
| `ErrKeyRevoked` | License was signed by a key explicitly marked as `REVOKED` | The key has been compromised or retired. Re-issue the license using an active signing key. |
| `ErrProductMismatch` | License was issued for a different Divmora product | Check that `-product` in the license matches the service product name. |
| `ErrExpired` | Current time is past `ExpiresAt` + clock skew tolerance | Re-issue a renewed license. |
| `ErrNotYetValid` | `NotBefore` is in the future | Check server system time / NTP sync. |
| `ErrFeatureNotEntitled` | Feature is not in `claims.Features` | Upgrade license tier or add feature flag during issuance. |
| `ErrLimitExceeded` | Current resource count exceeds `claims.Limits` | Increase quota limit during issuance. |
| `ErrCommercialLicenseRequired` | Operational usage or environment is not authorized under BSL 1.1 Additional Use Grants | Acquire and configure a commercial license key, or reduce resource usage below free tier bounds. |
| `ErrFingerprintMismatch` | License node/cluster fingerprint does not match host | Pass expected host fingerprint or check machine identity. |
| `ErrScopeMismatch` | Deployment environment, cloud account, region, host, or cluster is not allowed | Verify the license `Scope` allowlist contains the target deployment infrastructure. |
| `ErrVersionNotEntitled` | Running software version exceeds `claims.MaxVersion` or is not in `claims.AllowedVersions` | Upgrade perpetual license to entitle the newer major version. |
| `ErrMaintenanceExpired` | Software build date exceeds `claims.MaintenanceExpiresAt` | Customer's annual maintenance contract has expired. Renew maintenance to unlock newer binary releases. |
| `ErrClockTamperingDetected` | Local system clock was advanced forward to bypass BSL or license checks | Ensure the system clock is synchronized via NTP. Authoritative server time is used to enforce genuine validity. |
| `ErrDegradedMode` | License is expired or missing while operating in `PolicyDegraded` | Re-issue or restore valid commercial license key to unlock enterprise tier entitlements. |
| `ErrDegradedReadOnly` | Mutation attempted while manager is in degraded read-only mode (`DegradedReadOnly: true`) | Renew commercial license to re-enable write operations and full operational capacity. |
| `ErrInvalidReleaseAttestation` | Release attestation signature is invalid or token is malformed | Ensure the release attestation was signed with a trusted key in the KeyRing. |
| `ErrReleaseAttestationMissing` | Release attestation is required by policy (`WithRequireReleaseAttestation`) but missing | Provide an official release attestation sidecar (`release.sig`) with the binary. |
| `ErrReleaseTampered` | Binary build parameters (build date, release date, version, commit) contradict attested claims | Ensure the binary was compiled from official release sources without spoofed build metadata. |
| `ErrReleaseProductMismatch` | Release attestation was issued for a different product | Ensure the attestation matches the running binary product name. |
| `ErrReleaseVersionMismatch` | Release attestation version does not match running binary version | Verify that the release attestation matches the binary SemVer release. |
| `ErrReleaseDigestMismatch` | Compiled binary SHA-256 digest does not match the attested release digest | Ensure binary executable was not modified or corrupted after build. |


