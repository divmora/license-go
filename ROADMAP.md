# Living Product Roadmap: `license-go`

This document tracks upcoming capabilities, planned optimizations, and ecosystem integrations for the Divmora licensing package and CLI.

> [!NOTE]
> In accordance with [AGENTS.md](file:///Users/ngoyal16/divmora/github-repos/license-go/AGENTS.md), items are added when identified and pruned immediately once implemented, tested, and committed.

---

## 🎯 Upcoming Capabilities

### 🔑 Cryptographic & Key Lifecycle
- [ ] **AWS KMS Asymmetric Signing**: Support AWS KMS asymmetric Ed25519 signing in `license-cli` (enabling license generation in CI/CD without exposing private key files).
- [ ] **HashiCorp Vault Transit Engine**: Support Vault Transit engine for enterprise automated license issuance workflows.

### 🏢 Organizational Scoping & Multi-Tenancy
- [ ] *(Additional multi-tenancy capabilities will be tracked here)*

### 🛡️ Validation & Diagnostic Reporting
- [ ] *(Additional validation capabilities will be tracked here)*

### 🖥️ Developer Experience & CLI Tooling
- [ ] *(Additional CLI capabilities will be tracked here)*

### 📊 Concurrency-Safe Usage Metering & Watermarking
- [ ] **In-Memory `UsageMeter`**: Provide a thread-safe consumption tracker against `Claims.Limits` (e.g. `meter.CanConsume("runners", n)`).
- [ ] **Watermark Tracking & Threshold Alerts**: High-watermark usage recording and configurable threshold alert callbacks (e.g., notify downstream application when usage reaches 80% or 95% of licensed capacity).

### 🔌 Framework Adapters & Middleware
- [ ] **HTTP Server Middleware**: Standard Go `func(next http.Handler) http.Handler` to extract and verify tokens, inject `Claims` into `r.Context()`, and append telemetry headers (`X-License-Status`, `X-License-Expires`).
- [ ] **gRPC Interceptors**: Provide `UnaryServerInterceptor` and `StreamServerInterceptor` for Go microservices.

### 📦 Air-Gapped & Enterprise Workflows
- [ ] **Offline Revocation Lists (CRL)**: Support local cryptographically signed revocation lists to invalidate compromised or leaked license IDs in air-gapped environments without network access.
- [ ] **Signed Audit & Compliance Receipts**: Offline usage snapshot generator that outputs cryptographically signed receipts to verify historical compliance during vendor audits.

### 🌐 Online Activation & Centralized Revocation
- [ ] Optional HTTP client middleware for periodic online heartbeat / activation checks against a centralized Divmora licensing server.
- [ ] Centralized Cryptographic Revocation List (CRL) fetching and background caching.

### 📑 Ecosystem & Cross-Language Parity
- [ ] **`license-portal` Sync**: Update Cloudflare Pages Functions in `divmora/license-portal` to issue `DIV1` tokens and match the unified `Scope` and `Customer` schema.

### ⚡ Performance & Telemetry
- [ ] Zero-allocation validator optimizations for microservices processing high-frequency tenant licenses.
- [ ] Export Prometheus / OpenTelemetry metrics from `Manager` for license status, days remaining, active limits, and validation latency.

---

## ✅ Delivered Capabilities

- **Air-Gapped Machine Fingerprint Engine & Automated Resolvers (`MachineFingerprint`, `license-cli fingerprint`, `license-cli request`)**:
  - `MachineFingerprint`, `PlatformHost`, `PlatformAWSEC2`, `PlatformKubernetes`, `PlatformGeneric`: Deterministic machine identity schema with canonical SHA-256 digest computation, short 16-character digests, and flexible prefix/component-tolerant matching.
  - Out-of-the-box zero-dependency fingerprint resolvers:
    - `HostResolver`: Linux (`/etc/machine-id`, `/sys/class/dmi/id/product_uuid`), macOS (`ioreg` `IOPlatformExpertDevice` `IOPlatformUUID`), and non-loopback network MAC address fallback.
    - `AWSEC2Resolver`: Pure Go standard library IMDSv2 session token acquisition and dynamic instance identity document parsing (`instance_id`, `account_id`, `region`, `availability_zone`, `instance_type`) with strict 500ms safety timeout.
    - `KubernetesResolver`: In-cluster detection via serviceaccount secrets and Kubernetes API querying `kube-system` namespace UID, with downward API and cluster ID environment fallbacks.
    - `CompositeResolver`: Priority fallback resolver hierarchy (`Kubernetes` -> `AWSEC2` -> `Host`).
  - Air-gapped license request workflow:
    - `LicenseRequest`: Data structure and armored PEM block encoding `-----BEGIN DIVMORA LICENSE REQUEST-----` (`.divreq`).
    - Subcommand `license-cli fingerprint`: Inspects local host/cloud machine identity with visual inspection card, `-json`, and `-quiet` primary ID export.
    - Subcommand `license-cli request`: Generates air-gapped request files capturing target hardware identity, requested plan, limits, features, and operator notes.
    - Subcommand `license-cli issue -request <file>`: Automated fulfillment binding customer, product, plan, requested limits/features, and node-lock fingerprint from `.divreq` files.
  - Automated Validator node-lock enforcement:
    - `WithAutoFingerprint(true)`: Automatic detection and verification of node-locked licenses against host/cloud environment with zero manual configuration.
    - `WithFingerprintResolver(resolver)`: Custom resolver injection.
    - `VerificationResult.ResolvedFingerprint` and `VerificationResult.FingerprintMatched`: Enriched verification results and visual CLI status badges.

- **BSL 1.1 Additional Use Grant Evaluator (`BSLPolicy.EvaluateEntitlement` & `license-cli bsl-eval`)**:
  - `BSLAdditionalUseGrant`, `BSLUsageRequest`, `BSLGrantEvaluation`, `BSLEntitlementResult`, and `BSLGrantType`: Standardized BSL 1.1 dual-licensing entitlement evaluation engine modeling vendor-specific Additional Use Grants prior to Change Date.
  - Standard grant constructors: `NewNonProductionGrant` (unlimited non-production/staging/testing/dev exemption) and `NewFreeTierGrant` (free community production quota up to specified capacity bounds with commercial feature exclusions like SSO).
  - Autonomous open-source transition: When Change Date arrives, automatically converts to Apache 2.0 open-source, superseding all commercial requirements and grant restrictions.
  - Fail-closed commercial enforcement: Structured error `CommercialLicenseRequiredError` and sentinel `ErrCommercialLicenseRequired` (implementing `Is(ErrLicenseNotFound)` for backwards compatibility) when usage exceeds free tier limits or deployment occurs in non-exempt environments.
  - Seamless Validator integration: `validator.EvaluateBSLEntitlement(req)` and zero-license evaluation in `VerifyWithResultAt("", time.Now())` with `WithBSLGrants(...)`, `WithCurrentUsage(...)`, and `WithCurrentFeatures(...)`.
  - Terminal status badges & cards: Integrated into `FormatStatus()` rendering `BSL ADDITIONAL USE GRANT [✓ Entitled: ...]`.
  - Subcommand `license-cli bsl-eval`: First-class administrative tool evaluating operational context against BSL 1.1 terms with visual terminal cards and machine-readable `-json` output.
- **Standardized CLI License Status Formatter (`FormatStatus` & `license-cli status`)**:
  - `VerificationResult.FormatStatus(opts...)`, `VerificationResult.FormatStatusBanner(opts...)`, `Claims.FormatStatus(opts...)`, and `FormatStatus(...)`: Formats high-impact terminal status cards and quota utilization tables for downstream CLI applications (`app license status` or `license-cli status`).
  - Visual status badges: Clear badges for `ACTIVE [✓ Valid]`, `GRACE PERIOD [⚠️ Operating under grace buffer]`, `OPEN SOURCE [✓ Converted to Apache-2.0]`, `EXPIRED [❌ Commercial License Expired]`, and `PENDING [⏳ Not active yet]`.
  - Live runtime usage overlay: Supports `WithStatusUsage(map[string]int64)` and `WithStatusUsageFunc(fn)` to calculate live percentage utilization (`71%`), available headroom (`58 available`), and over-quota warnings (`130% [EXCEEDED]`, `OVER QUOTA (+15)`).
  - Open-source transition countdown: Displays remaining days until BSL 1.1 converts to Apache 2.0.
  - Subcommand `license-cli status`: First-class administrative tool supporting `-license`, `-usage`, `-compact`, `-title`, and zero-configuration environment auto-resolution.
- **Cryptographic Release Attestation & Provenance Engine (`DIVREL1` & `EvaluateProvenance`)**:
  - `ReleaseClaims`, `SignRelease`, `SignReleaseArmored`, `VerifyRelease`, `InspectRelease`, and `InspectReleaseFromFile`: End-to-end cryptographic minting and verification of release provenance metadata.
  - Wire format `DIVREL1` (`DIVREL1.<payloadB64>.<sigB64>`) and armored PEM block `-----BEGIN DIVMORA RELEASE ATTESTATION-----`.
  - Binary integrity checksum verification: SHA-256 binary digest evaluation via `ComputeBytesDigest`, `ComputeReaderDigest`, and `ComputeFileDigest`.
  - Comprehensive anti-tampering assertions: Validates product identity, SemVer version normalization, Git commit SHA prefix matching, and build date consistency (>24h earlier drift detection).
  - BSL 1.1 compile-time spoofing defeat: Cross-checks local release dates against certified release claims and anchors `BSLPolicy.ReleaseDate` to prevent attackers from forging build timestamps to claim premature Apache 2.0 open-source conversion.
  - Fail-closed enforcement: `WithRequireReleaseAttestation(true)` mandates valid release attestation before granting commercial or open-source entitlements.
  - CLI subcommands: `license-cli sign-release`, `license-cli verify-release`, `license-cli inspect-release`, and integrated `-release-attestation`, `-require-release-attestation`, `-binary`, and `-git-commit` flags in `license-cli verify`.
- **Reusable Terminal Claims Inspection Formatter (`Claims.FormatInspect()`)**:
  - `Claims.FormatInspect()` and `Claims.FormatInspectAt(t)`: Reusable, aligned terminal formatter presenting complete claims metadata (Status, Customer, Plan, Product, Validity Timeline, Version Bounds, Maintenance Cutoff, Entitlements & Limits, Operational Infrastructure Scopes, and Custom Metadata) with deterministic sorting.
  - `VerificationResult.FormatInspect()`: Enriched terminal inspector combining cryptographic signature verification status, key lifecycle status, BSL 1.1 transition status, and authoritative clock attestation with formatted claims.
  - `license-cli inspect` formatted inspection: Defaults to `claims.FormatInspect()` with a `-json` flag for raw JSON output.
- **Diagnostic Human Status Message (`VerificationResult.StatusMessage()`)**:
  - `VerificationResult.StatusMessage()`: Standard human-readable descriptions of operational validity, covering active subscriptions with remaining days, in-grace-period notices with remaining grace days and cutoff countdown, perpetual active status, future `NotBefore` activation windows, BSL 1.1 open-source transition notices, and past-expiration notices with grace period summaries.
  - `Claims.StatusMessage()` and `Claims.StatusMessageAt(t)`: Reusable claims status formatting for unverified inspection, daemon logs, and custom telemetry.
  - `Claims.DaysRemainingAt(t)`: Time-anchored days remaining evaluator supporting arbitrary reference timestamps.
  - Standardized CLI output across `license-cli verify` and `license-cli inspect`.
- **Authoritative Server Time Attestation & Clock Skew Defense (`WithServerTimeAttestation`)**:
  - `WithServerTimeAttestation(serverTime, maxAllowedSkew)`: Validates licenses against authoritative external server timestamps (e.g. from HTTP response `Date` headers, cloud metadata, or central licensing API) with configurable maximum allowed clock drift/skew threshold.
  - `WithServerTimeHeader(headerValue, maxAllowedSkew)` and `ParseServerTimeHeader`: Multi-format parser supporting HTTP Date (RFC 1123, RFC 1123Z, RFC 850, ANSI C), ISO 8601/RFC 3339, and SQL timestamp formats.
  - Clock tampering defense: Defeats both backward clock tampering (attempting to keep expired licenses active) and forward clock tampering (attempting to trigger premature BSL 1.1 open-source conversion or skip `NotBefore`), securely anchoring claims evaluation to the authoritative server time.
  - `WithStrictClockDefense(strict)` and typed `ClockTamperingError`: Enables immediate rejection with `ErrClockTamperingDetected` when skew threshold is violated.
  - Detailed reporting in `VerificationResult`: Exposes `ServerTimeAttested`, `ServerTime`, `ClockSkew`, and `ClockTampered`.
  - CLI flags for `license-cli verify`: `-authoritative-time`, `-max-skew`, and `-strict-clock`.
- **Hierarchical Namespace & Group Tree Scope Matching (`Scope.Namespaces`)**:
  - `NormalizeNamespace` utility to automatically strip schemes (`https://`, `http://`, `git://`, `ssh://`, `//`), SCP git syntax (`git@gitlab.com:org/repo.git`), user credentials, ports, trailing `.git` extensions, query parameters, and fragments.
  - Hierarchical tree path matching: scopes like `"devops"` or `"devops/*"` authorize root group `"devops"` as well as all descendant sub-groups and repositories (`"devops/backend/service"`).
  - Prefix collision security defenses: strictly enforces path segment boundaries to disallow sibling collisions (`"devops"` and `"devops/*"` reject `"devops-tools"`, `"devops_infra"`, or `"devops-prod"`).
  - Wildcard domain namespace pattern support (e.g. `"*.internal/devops/*"` authorizes both subdomains and apex `"internal/devops/repo"`).
  - First-class evaluator helper methods `Scope.IsNamespaceAllowed` and `Claims.IsNamespaceAllowed`.
- **Standard Verification KeyRing & Environment Resolver (`ResolveKeyRing`)**:
  - Auto-resolution across programmatic in-memory overrides (`SetVerificationKeyRing`, `SetVerificationPublicKey`), `DIVMORA_PUBLIC_KEYS_PEM` (multi-key PKIX PEM bundle string or file path), `DIVMORA_PUBLIC_KEY` (base64 raw 32-byte key, base64 PKIX DER, inline PEM, or file path), `DIVMORA_PUBLIC_KEY_FILE`, default `/etc/divmora/public.pem`, and embedded fallback keys.
  - Zero-configuration CLI verification (`license-cli verify` and `license-cli keyring` without requiring `-public-key`).
- **Host / URL Normalization & Apex Domain Matching (`Scope.Hosts`)**:
  - `NormalizeHost` utility to automatically strip schemes (`http://`, `https://`, `grpc://`, `//`), user credentials, ports (`:8080`), paths, query strings, and fragments with full IPv4 and IPv6 support.
  - Automatic apex domain authorization for wildcard domain scopes (`*.acme.corp` authorizes both subdomains like `gitlab.acme.corp` and apex `acme.corp`).
  - First-class evaluator helper methods on `Scope` (`Scope.IsHostAllowed`, `Scope.IsEnvironmentAllowed`, `Scope.IsAccountAllowed`, `Scope.IsRegionAllowed`, `Scope.IsClusterAllowed`, `Scope.IsNamespaceAllowed`).
- **Embedded Public Key Helpers & Constructors**:
  - `NewValidatorFromEmbeddedPEM` for compile-time `//go:embed` directives without distributing separate `.pem` files on disk.
  - `NewValidatorFromBase64`, `NewValidatorFromEnv`, and `NewValidatorWithFallbackKey`.
- **Divmora Token Protocol Specification (`SPEC.md`)**:
  - Full RFC specification covering `DIV1` envelope encoding, Ed25519 digital signatures, canonical signed data (`DIV1.<payloadB64>`), JSON claims schema, BSL 1.1 state machine, operational policies, and strict 10-step verification algorithm.
- **Operational Enforcement Policies & Graceful Degradation (`Manager`)**:
  - `PolicyStrict`: Fail-closed enforcement on expiration, scope mismatch, or verification failure.
  - `PolicyDegraded`: Continuous operation with fallback community claims, read-only mutation restrictions (`DegradedReadOnly`), and non-disruptive `OnDegraded` and `OnRecovered` lifecycle hooks.
  - `PolicyWarnOnly`: Non-blocking audit/dry-run mode that records policy violations without rejecting features or limits.
  - Runtime BSL 1.1 open-source recovery with `OnBSLConverted` notification hook.
- **Business Source License (BSL 1.1) Dual-Lifecycle & Clock Defense**:
  - Autonomous 3-year conversion to open-source (`Apache-2.0`) with synthetic entitlement bypass.
  - Authoritative reference clock defense (`WithAuthoritativeTime`) to detect forward host clock tampering.
- **Perpetual License Version Locking & Maintenance Cutoffs**:
  - `MaxVersion` and `AllowedVersions` zero-dependency SemVer upper-bound constraints.
  - `MaintenanceExpiresAt` binary build timestamp cutoff enforcement.
- **KeyRing Multi-Key Rotation & Revocation**:
  - Multi-key PEM bundle parsing and serialization.
  - Active, retiring, and revoked key lifecycle statuses with zero-downtime key rotation.
  - Instant cryptographic revocation with `ErrKeyRevoked`.
- **Infrastructure & Organizational Scoping**:
  - Fine-grained matching across cloud environments, accounts, regions, clusters, namespaces, hosts, and custom dimensions.
- **Grace Period Dynamics**:
  - Operational buffer between license expiration and hard service shutoff, exposed in `VerificationResult`.
- **Background Daemon Manager (`Manager`)**:
  - Thread-safe background monitoring, hot-reloading from files/environment, and proactive warning callbacks.
- **Zero-Dependency Ed25519 Core**:
  - Asymmetric Ed25519 cryptography using Go standard library exclusively.
  - Compact `DIV1.<payload>.<sig>` tokens and armored PEM block encoding.
- **Standalone CLI Toolkit (`license-cli`)**:
  - Subcommands for `keygen`, `issue`, `verify`, `inspect`, and `keyring` bundle inspection.

