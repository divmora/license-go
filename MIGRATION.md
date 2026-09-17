# Migration Guide: Architecture Restructuring & Issuance Decoupling

This document guides engineering teams across Divmora through the architectural restructuring in `license-go`, encapsulating internal subsystems and segregating license issuance from the public consumer SDK.

---

## 1. Security Rationale & Motivation

Prior to this architecture update, `github.com/divmora/license-go/pkg/license` contained both consumer verification logic (public keys, `Validator`, `Manager`, `Claims`) and vendor issuance logic (`Signer`, `GenerateKeyPair`, private key PEM encoders).

This presented critical security and architectural concerns:
1. **Asymmetric Security Leakage**: Consuming microservices (such as `gitlab-fleet-governor` and `otel-aws-log-processor`) imported `pkg/license` and inadvertently had access to private key generation and license signing types in their namespace, increasing the risk of accidental exposure or misuse.
2. **Namespace Pollution**: Internal string manipulators, semver parsers, file checkers, and wire formatting functions were scattered across public files.
3. **Dedicated Issuance Architecture**: Divmora operates an internal license issuance portal and standalone CLI (`cmd/license-cli`). Downstream services are strictly consumers and must never possess issuance capabilities.

To resolve this, all internal subsystems have been relocated to Go `internal/` packages, and `pkg/license` is now strictly a **consumer verification SDK**.

---

## 2. Package Organization

```
license-go/
├── pkg/
│   └── license/            # Public Consumer SDK (Verification, Claims, KeyRing, Manager, BSL)
├── internal/               # Restricted Subsystems (Compiler-enforced: only accessible inside repo)
│   ├── helpers/            # String formatting, SemVer comparison, constant-time crypto match, file I/O
│   ├── envelope/           # DIV1 token wire packing, unpacking, and armored PEM block parsing
│   ├── schema/             # JSON claims validation & required field assertions
│   ├── resolvers/          # Platform fingerprint resolvers (Host, EC2, Lambda, K8s, Generic Container)
│   └── issuer/             # Ed25519 private key generation, PEM I/O, and signing engine
└── cmd/
    └── license-cli/        # Standalone CLI (imports internal/issuer and pkg/license)
```

---

## 3. Public API Changes & Deprecations

### Removed from `pkg/license` (Breaking Changes)

The following types and functions have been removed from `pkg/license`:

| Removed Symbol | Replacement / Status |
| :--- | :--- |
| `license.Signer` | Moved to `internal/issuer.Signer` (accessible only to `cmd/license-cli` and internal generator tools). |
| `license.NewSigner(...)` | Moved to `internal/issuer.NewSigner(...)`. |
| `license.GenerateKeyPair()` | Moved to `internal/issuer.GenerateKeyPair()`. |
| `license.EncodePrivateKeyToPEM(...)` | Moved to `internal/issuer.EncodePrivateKeyToPEM(...)`. |
| `license.ParsePrivateKeyFromPEM(...)` | Moved to `internal/issuer.ParsePrivateKeyFromPEM(...)`. |
| `license.SavePrivateKeyToPEMFile(...)` | Moved to `internal/issuer.SavePrivateKeyToPEMFile(...)`. |
| `license.LoadPrivateKeyFromPEMFile(...)` | Moved to `internal/issuer.LoadPrivateKeyFromPEMFile(...)`. |
| `license.SignRelease(...)` | Moved to `internal/issuer.SignRelease(...)`. |
| `license.SignReleaseArmored(...)` | Moved to `internal/issuer.SignReleaseArmored(...)`. |
| `license.PEMTypePrivateKey` | Moved to `internal/issuer.PEMTypePrivateKey`. |

### Preserved in `pkg/license` (Zero Changes for Downstream Consumers)

All public verification, claims evaluation, and daemon management APIs remain unchanged:
- **Validators**: `NewValidator`, `NewValidatorFromPEM`, `NewValidatorFromPEMFile`, `NewValidatorFromEnv`, `NewValidatorFromEmbeddedPEM`, `NewValidatorWithFallbackKey`.
- **Validation Methods**: `Verify` (supports both compact tokens and armored PEM blocks), `VerifyFromFile`, `VerifyEnv`, `VerifyResolved`.
- **Manager**: `NewManager`, `ManagerConfig`, `Start`, `Stop`, `Claims`, `HasFeature`, `AssertFeature`, `CheckLimit`.
- **KeyRing**: `NewKeyRing`, `KeyRingFromPEM`, `ResolveKeyRing`, `ResolvePublicKey`.
- **Claims & Scoping**: `Claims`, `Customer`, `Scope`, `Status`, feature checks, quota checks, version bounds.
- **BSL 1.1**: `BSLPolicy`, `BSLAdditionalUseGrant`, `NewNonProductionGrant`, `NewFreeTierGrant`.
- **Release Attestation**: `VerifyRelease`, `VerifyReleaseArmored`, `VerifyReleaseBinary`, `EvaluateProvenance`.
- **Hardware Fingerprint**: `MachineFingerprint`, `Platform`, `DetectEnvironment`, `AutoDetectResolver`.

---

## 4. Downstream Migration Guide

### For Consuming Services (`gitlab-fleet-governor`, `otel-aws-log-processor`)

If your service only verifies licenses using public keys, **no code changes are required**. Update your `go.mod` dependency as normal:

```bash
go get github.com/divmora/license-go@latest
```

### For Unit Tests in Downstream Services

If downstream unit tests previously generated dynamic keypairs and signed mock licenses using `license.GenerateKeyPair()` and `license.NewSigner()`:

**Recommended Approach**:
1. Pre-generate a test public/private keypair using `license-cli keygen -out-dir testdata/`.
2. Generate fixture licenses for test scenarios using `license-cli issue`.
3. In tests, embed or load the fixture license and test public key.
4. Alternatively, mock the `*license.Claims` directly in your application's interfaces without requiring cryptographic verification in unit test suites.

### For License Issuance Tools & Services

Applications that issue licenses (such as the Divmora License Portal or `cmd/license-cli`) must reside within or build directly from the `license-go` repository to access `internal/issuer`.

Example:

```go
import (
    "github.com/divmora/license-go/internal/issuer"
    "github.com/divmora/license-go/pkg/license"
)

// Generate keypair
privKey, pubKey, err := issuer.GenerateKeyPair()

// Initialize signer
signer, err := issuer.NewSigner(privKey, "kid-2026")

// Sign claims
claims := license.Claims{ ... }
token, err := signer.SignArmored(claims)
```
