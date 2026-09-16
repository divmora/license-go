# license-go

[![Latest Release](https://img.shields.io/github/v/release/divmora/license-go?logo=github)](https://github.com/divmora/license-go/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI/CD](https://github.com/divmora/license-go/actions/workflows/ci.yml/badge.svg)](https://github.com/divmora/license-go/actions)
[![Go Version](https://img.shields.io/github/go-mod/go-version/divmora/license-go)](go.mod)
[![Security Policy](https://img.shields.io/badge/Security-Policy-green.svg)](SECURITY.md)

`license-go` is the centralized, secure Go licensing framework and CLI for the Divmora organization. It eliminates duplicated licensing implementations across products such as **`gitlab-fleet-governor`** and **`otel-aws-log-processor`**, providing a unified claims schema, Ed25519 cryptographic signing and verification, and an embeddable client SDK.

---

## Key Features

- **Asymmetric Cryptography (Ed25519)**: Fast, compact, tamper-proof license generation and verification.
- **Zero External Crypto Dependencies**: Built purely on Go standard library (`crypto/ed25519`, `crypto/x509`, `encoding/pem`). No CGo or heavy third-party bloat.
- **Dual Representation**:
  - **Armored Text Blocks**: Human-friendly files with boundary headers (`-----BEGIN DIVMORA LICENSE KEY-----`).
  - **Compact Tokens**: Single-line `DIV1.<payload>.<signature>` strings for environment variables and CLI arguments.
- **Rich Claims Schema**: Supports customer details, product targeting, subscription tiers (`community`, `starter`, `pro`, `enterprise`, `trial`), expiration dates, feature flags, numerical quotas/limits, and custom key-value metadata.
- **Background Daemon Manager**: Built-in `Manager` for long-running services with hot-reloading from disk and automated expiration warnings.
- **CLI Included**: `cmd/license-cli` provides instant `keygen`, `issue`, `verify`, and `inspect` subcommands for CI/CD and administration.

---

## Installation

```bash
go get github.com/divmora/license-go
```

To install the CLI tool:
```bash
go install github.com/divmora/license-go/cmd/license-cli@latest
```

---

## Quickstart: Client Integration

### 1. Simple Verification

In your product (e.g. `gitlab-fleet-governor` or `otel-aws-log-processor`):

```go
package main

import (
	"fmt"
	"log"

	license "github.com/divmora/license-go/pkg/license"
)

// Divmora public key (can be embedded or loaded from config/secret)
const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----`

func main() {
	// 1. Create a validator configured for your product
	validator, err := license.NewValidatorFromPEM(
		[]byte(publicKeyPEM),
		license.WithProduct("gitlab-fleet-governor"),
	)
	if err != nil {
		log.Fatalf("failed to initialize validator: %v", err)
	}

	// 2. Verify license automatically from environment (DIVMORA_LICENSE_KEY / DIVMORA_LICENSE_FILE / /etc/divmora/license.key)
	// Or explicitly pass a file path: validator.VerifyFromFile("/etc/divmora/license.key")
	claims, err := validator.VerifyEnv()
	if err != nil {
		log.Fatalf("License verification failed: %v", err)
	}

	fmt.Printf("Licensed to: %s (Plan: %s)\n", claims.Customer.Name, claims.Plan)
	fmt.Printf("Days remaining: %d\n", claims.DaysRemaining())

	// 3. Check feature entitlements
	if claims.HasFeature("ha") {
		fmt.Println("High Availability mode enabled")
	}

	// 4. Enforce quota limits
	currentRunners := int64(120)
	if err := claims.CheckLimit("max_runners", currentRunners); err != nil {
		log.Fatalf("Quota exceeded: %v", err)
	}
}
```

---

### 2. Standardized Environment Resolution

`license-go` provides standardized resolution hierarchies eliminating custom loading boilerplate for both licenses and verification public keys:

#### License Resolution Hierarchy

| Priority | Source | Description |
| :--- | :--- | :--- |
| **1** | `explicitSource` argument | Direct file path or inline token string passed to `ResolveToken()`, `VerifyResolved()`, or `-license` CLI flag. |
| **2** | `DIVMORA_LICENSE_KEY` | Environment variable containing raw compact token (`DIV1...`) or armored PEM block text. Ideal for Docker, Lambda, and 12-factor apps. |
| **3** | `DIVMORA_LICENSE_FILE` | Environment variable containing filesystem path to license file. Ideal for Kubernetes Secrets & ConfigMap mounts. |
| **4** | `/etc/divmora/license.key` | Default Linux/container filesystem location if file exists. |

#### Public Verification KeyRing Resolution Hierarchy

| Priority | Source | Description |
| :--- | :--- | :--- |
| **0** | Programmatic Override | In-memory override via `SetVerificationPublicKey(key)` or `SetVerificationKeyRing(ring)` (ideal for automated unit/integration tests). |
| **1** | `DIVMORA_PUBLIC_KEYS_PEM` | Multi-key or single-key PKIX PEM bundle text string or filesystem path. |
| **2** | `DIVMORA_PUBLIC_KEY` | Single Ed25519 public key (base64 raw 32-byte, base64 PKIX DER, inline PEM, or filesystem path). |
| **3** | `DIVMORA_PUBLIC_KEY_FILE` | Filesystem path to public key file on disk. |
| **4** | `/etc/divmora/public.pem` | Default Linux/container filesystem location if file exists. |
| **5** | `fallbackKeys...` | Embedded fallback public keys passed to `ResolveKeyRing()` or `NewValidatorWithFallbackKey()`. |

```go
// Direct resolution helpers:
token, err := license.ResolveToken() // Returns license token string from env/file
resolved, err := license.ResolveLicense() // Returns content + FilePath for hot reloading

// Public verification KeyRing resolution:
ring, err := license.ResolveKeyRing(embeddedFallbackKey) // Resolves trusted KeyRing
pubKey, err := license.ResolvePublicKey(embeddedFallbackKey) // Resolves primary public key

// Zero-boilerplate validator initialization:
validator, err := license.NewValidatorFromEnv(license.WithProduct("gitlab-fleet-governor"))
// Or compile-time //go:embed helper:
// //go:embed public.pem
// var embeddedPublicKey []byte
validator, err := license.NewValidatorFromEmbeddedPEM(embeddedPublicKey, license.WithProduct("gitlab-fleet-governor"))
```

---

### 3. Daemon Background Manager (Hot-Reloading & Expiry Alerts)

For long-running microservices and daemons, use `license.NewManager`. If `LicenseFile` and `LicenseString` are omitted, `Manager` automatically resolves from `DIVMORA_LICENSE_FILE` (enabling hot-reloading) or `DIVMORA_LICENSE_KEY`:

```go
package main

import (
	"context"
	"log"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func main() {
	validator, err := license.NewValidatorFromPEMFile(
		"/etc/divmora/public.pem",
		license.WithProduct("otel-aws-log-processor"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Auto-resolves from DIVMORA_LICENSE_FILE or DIVMORA_LICENSE_KEY if LicenseFile is omitted:
	mgr, err := license.NewManager(license.ManagerConfig{
		Validator:         validator,
		CheckInterval:     1 * time.Hour,
		ExpiryWarningDays: 14,
		OnExpiringSoon: func(c *license.Claims, daysRemaining int) {
			log.Printf("WARNING: License expires in %d days!", daysRemaining)
		},
		OnGracePeriod: func(c *license.Claims, graceDaysRemaining int) {
			log.Printf("NOTICE: License operating in grace period (%d days left)!", graceDaysRemaining)
		},
		OnExpired: func(c *license.Claims) {
			log.Printf("CRITICAL: License has expired!")
		},
		OnReloaded: func(newClaims, oldClaims *license.Claims) {
			log.Printf("INFO: License reloaded! New tier: %s", newClaims.Plan)
		},
		OnError: func(err error) {
			log.Printf("License check error: %v", err)
		},
	})
	if err != nil {
		log.Fatalf("License initialization failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background monitoring and file watching
	mgr.Start(ctx)
	defer mgr.Stop()

	// Thread-safe queries anytime in your service:
	if mgr.HasFeature("s3_export") {
		// enable S3 exporter...
	}
}
```

---

## Claims Structure Reference

```go
type Customer struct {
    Name  string `json:"name"`
    Email string `json:"email,omitempty"`
    OrgID string `json:"org_id,omitempty"`
}

type Scope struct {
    Environments []string            `json:"environments,omitempty"` // ["production", "staging"]
    Accounts     []string            `json:"accounts,omitempty"`     // AWS Account IDs, cloud tenant IDs
    Regions      []string            `json:"regions,omitempty"`      // Cloud regions ["us-east-1", "eu-west-*"]
    Clusters     []string            `json:"clusters,omitempty"`     // Kubernetes / ECS cluster IDs
    Namespaces   []string            `json:"namespaces,omitempty"`   // GitLab groups/projects ["acme-corp/*"]
    Hosts        []string            `json:"hosts,omitempty"`        // Hostnames, FQDNs, domains ["*.acme.corp"]
    Custom       map[string][]string `json:"custom,omitempty"`       // Arbitrary product scope dimensions
}

type Claims struct {
    ID              string            `json:"id"`
    Customer        Customer          `json:"customer"`
    Product         string            `json:"product"`  // Product name, suite ("divmora-suite"), or wildcard ("*")
    Plan            string            `json:"plan"`     // "community", "starter", "pro", "enterprise", "trial"
    IssuedAt        time.Time         `json:"issued_at"`
    NotBefore       time.Time         `json:"not_before,omitempty"`
    ExpiresAt       time.Time         `json:"expires_at"` // zero time = perpetual
    GracePeriodDays int               `json:"grace_period_days,omitempty"` // Buffer days after ExpiresAt
    Features        []string          `json:"features,omitempty"`
    Limits          map[string]int64  `json:"limits,omitempty"`   // -1 = unlimited
    Scope           *Scope            `json:"scope,omitempty"`    // Scoping constraints
    Environment     string            `json:"environment,omitempty"`
    Fingerprint     string            `json:"fingerprint,omitempty"`
    Metadata        map[string]string `json:"metadata,omitempty"`
}
```

### Useful Evaluation Methods

- `claims.IsValidForProduct(name string) bool` (supports exact match, wildcards `*` / `all`, suite bundles `divmora-suite` / `suite`, multi-product lists, and glob patterns)
- `claims.HasFeature(name string) bool` (supports exact match, wildcards `*` / `all`, and glob patterns like `audit:*`)
- `claims.IsInGracePeriod() bool` (true if passed `ExpiresAt` but within `GracePeriodDays`)
- `claims.GraceDaysRemaining() int` (remaining grace buffer days before hard cutoff)
- `claims.EffectiveExpiration() time.Time` (final cutoff: `ExpiresAt + GracePeriodDays`)
- `claims.Status() Status` (returns `ACTIVE`, `GRACE_PERIOD`, `EXPIRED`, or `NOT_YET_VALID`)
- `claims.IsBoundToFingerprint() bool` (true if license is bound to a specific node/cluster)
- `claims.MatchesFingerprint(hostFingerprint string) bool` (case-insensitive fingerprint evaluation)
- `claims.IsInScope(dimension, target string) bool` (checks authorization against any scope dimension)
- `claims.IsEnvironmentAllowed(env string) bool`
- `claims.IsAccountAllowed(account string) bool`
- `claims.IsRegionAllowed(region string) bool`
- `claims.IsClusterAllowed(cluster string) bool`
- `claims.IsNamespaceAllowed(namespace string) bool`
- `claims.IsHostAllowed(host string) bool`
- `claims.AssertScope(dimension, target string) error`
- `claims.AssertFeature(name string) error`
- `claims.CheckLimit(name string, currentUsage int64) error`
- `claims.IsPerpetual() bool`
- `claims.IsExpired() bool`
- `claims.DaysRemaining() int`
- `claims.GetMetadata(key string) (string, bool)`

---

## CLI Usage

### 1. Generate Keypair

```bash
license-cli keygen -out-dir ./keys
```
Outputs:
- `./keys/private.pem` (mode 0600 - keep secure, Divmora internal only)
- `./keys/public.pem` (mode 0644 - embed or distribute with products)

### 2. Issue a License

```bash
license-cli issue \
  -private-key ./keys/private.pem \
  -customer "Acme Corp" \
  -email "admin@acme.corp" \
  -org-id "org_acme_corp_01" \
  -product "gitlab-fleet-governor" \
  -plan enterprise \
  -valid-days 365 \
  -grace-days 14 \
  -features "ha,audit-logs,auto-scaling" \
  -limits "max_runners=200,max_nodes=10" \
  -scope-envs "production" \
  -scope-accounts "123456789012" \
  -scope-regions "us-east-1,eu-west-1" \
  -scope-clusters "prod-eks-01" \
  -scope-namespaces "gitlab.com/acme-corp/*" \
  -scope-hosts "*.acme.corp" \
  -scope-custom "tier=platinum,gold;datacenter=dc-east,dc-west" \
  -meta "billing_id=inv-9981,contact=admin@acme.corp" \
  -fingerprint "node-cluster-01" \
  -out ./acme.license.key
```

### 3. Verify a License

```bash
# Verify explicit license with optional scope assertion flags:
license-cli verify \
  -public-key ./keys/public.pem \
  -product "gitlab-fleet-governor" \
  -env "production" \
  -namespace "gitlab.com/acme-corp/fleet" \
  -host "runner-01.acme.corp" \
  -custom-scope "tier=platinum,datacenter=dc-east" \
  -fingerprint "node-cluster-01" \
  -license ./acme.license.key

# Or verify automatically with zero configuration (resolves license from DIVMORA_LICENSE_KEY/FILE
# and public key from DIVMORA_PUBLIC_KEY / DIVMORA_PUBLIC_KEYS_PEM / /etc/divmora/public.pem):
license-cli verify -product "gitlab-fleet-governor"

# Verify license enforced with release attestation sidecar and binary checksum:
license-cli verify \
  -product "gitlab-fleet-governor" \
  -license ./acme.license.key \
  -release-attestation ./release.sig \
  -binary ./bin/gitlab-fleet-governor \
  -require-release-attestation
```

### 4. Display Standardized License Status Card (`license-cli status`)

Display a visual status card with active tier, countdown, BSL 1.1 open-source transition, and resource quota utilization table:

```bash
# Display status with live runtime usage counts:
license-cli status \
  -product "gitlab-fleet-governor" \
  -license ./acme.license.key \
  -usage "max_runners=142,max_nodes=6"

# Or display compact status card from environment:
license-cli status -compact
```

### 5. Inspect a License (No Key Required)

```bash
# Direct file / token inspect:
license-cli inspect -license ./acme.license.key

# Or inspect automatically from $DIVMORA_LICENSE_KEY or $DIVMORA_LICENSE_FILE:
license-cli inspect
```

### 6. Mint a Release Attestation (CI/CD Pipeline)

Mint an Ed25519 cryptographic release attestation token or armored PEM sidecar (`release.sig`) in your CI/CD release build step to certify binary build authenticity, official Git commit, SemVer version, authoritative BSL 1.1 release date, and binary SHA-256 digest:

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

### 7. Verify Release Provenance & Binary Integrity

Verify an official release binary against a cryptographic release attestation:

```bash
license-cli verify-release \
  -public-key ./keys/public.pem \
  -attestation ./bin/release.sig \
  -product "gitlab-fleet-governor" \
  -version "v2.5.0" \
  -git-commit "${CI_COMMIT_SHA}" \
  -binary "./bin/gitlab-fleet-governor"
```

### 8. Inspect Release Attestation Claims (No Key Required)

Inspect the unverified release claims embedded within an armored `.sig` file or compact token:

```bash
# Standard formatted inspection:
license-cli inspect-release -attestation ./bin/release.sig

# Or output raw JSON:
license-cli inspect-release -attestation ./bin/release.sig -json
```

---

## Development & Building

This repository provides standardized `make` targets:

```bash
make build         # Compile license-cli binary into bin/
make test          # Run all unit and integration tests
make test-race     # Run tests with race detector
make test-coverage # Generate coverage report
make fmt           # Format code
make lint          # Run golangci-lint
make clean         # Remove temporary build artifacts
```

---

## Documentation & Specifications

- **[Protocol Specification (`SPEC.md`)](SPEC.md)**: Formal RFC specification covering `DIV1` envelope encoding, Ed25519 cryptography, canonical data signing, JSON claims schema, BSL 1.1 state machine, operational policies, and strict 10-step verification algorithm.
- **[Living Product Roadmap (`ROADMAP.md`)](ROADMAP.md)**: Upcoming capabilities and delivered enterprise features.
- **[Contributing Guide](CONTRIBUTING.md)**: Development setup, make targets, and Conventional Commits guidelines.
- **[Code of Conduct](https://github.com/divmora/.github/blob/main/CODE_OF_CONDUCT.md)**: Community standards and expectations.
- **[Security Policy](SECURITY.md)**: Responsible vulnerability disclosure and 48-hour response SLA.

---

## License

This software is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for complete terms and conditions.

Copyright (c) 2026 DIVMORA Technologies.
