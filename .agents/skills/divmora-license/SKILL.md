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
  -out ./license.key \
  -armored
```

For perpetual licenses, pass `-valid-days 0`.

---

### Workflow C: Verify or Inspect a License via CLI

```bash
# Verify explicit license file or token:
license-cli verify \
  -public-key /path/to/public.pem \
  -product "<product-name>" \
  -fingerprint "<host-fingerprint>" \
  -license ./license.key

# Or verify automatically from $DIVMORA_LICENSE_KEY or $DIVMORA_LICENSE_FILE:
license-cli verify \
  -public-key /path/to/public.pem \
  -product "<product-name>"

# Inspect claims without signature verification (direct or env fallback)
license-cli inspect -license ./license.key
license-cli inspect
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
const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----`

func checkLicense() {
	validator, err := license.NewValidatorFromPEM(
		[]byte(publicKeyPEM),
		license.WithProduct("gitlab-fleet-governor"),
	)
	if err != nil {
		log.Fatalf("failed to initialize validator: %v", err)
	}

	// Automatically resolves from DIVMORA_LICENSE_KEY, DIVMORA_LICENSE_FILE,
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
		OnExpiringSoon: func(claims *license.Claims, daysRemaining int) {
			log.Printf("[LICENSE] Warning: License expires in %d days", daysRemaining)
		},
		OnGracePeriod: func(claims *license.Claims, graceDaysRemaining int) {
			log.Printf("[LICENSE] Notice: Operating in grace period (%d days remaining)", graceDaysRemaining)
		},
		OnExpired: func(claims *license.Claims) {
			log.Printf("[LICENSE] CRITICAL: License has expired!")
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

## 4. Troubleshooting & Sentinel Errors

| Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ErrInvalidSignature` | License payload or signature was altered or signed by an untrusted key | Verify that the license was signed with the corresponding private key and has not been modified. |
| `ErrProductMismatch` | License was issued for a different Divmora product | Check that `-product` in the license matches the service product name. |
| `ErrExpired` | Current time is past `ExpiresAt` + clock skew tolerance | Re-issue a renewed license. |
| `ErrNotYetValid` | `NotBefore` is in the future | Check server system time / NTP sync. |
| `ErrFeatureNotEntitled` | Feature is not in `claims.Features` | Upgrade license tier or add feature flag during issuance. |
| `ErrLimitExceeded` | Current resource count exceeds `claims.Limits` | Increase quota limit during issuance. |
