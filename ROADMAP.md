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
- [ ] **Hierarchical Namespace & Group Tree Scope Matching (`Scope.Namespaces`)**: Extend `Scope.IsNamespaceAllowed` to support hierarchical path matching (e.g., `"devops"` or `"devops/*"` authorizes all descendant sub-groups and repositories like `"devops/backend/service"`). Supports multi-tenant trees in GitLab groups, GitHub organizations, and Kubernetes namespace hierarchies.

### 🛡️ Validation & Diagnostic Reporting
- [ ] **Diagnostic Human Status Message (`VerificationResult.StatusMessage()`)**: Add `StatusMessage()` on `VerificationResult` generating standard human-readable descriptions (active status with remaining days, in-grace-period notices with remaining grace days, perpetual active status, and expired notices) to unify CLI banners and log messaging across products.
- [ ] **Authoritative Server Time Attestation & Clock Skew Defense (`WithServerTimeAttestation`)**: Add a `ValidatorOption` to validate licenses against an authoritative external server timestamp (e.g., parsed from HTTP response `Date` headers) with a configurable maximum allowed skew threshold to prevent local client clock tampering.

### 🖥️ Developer Experience & CLI Tooling
- [ ] **Reusable Terminal Claims Inspection Formatter (`Claims.FormatInspect()`)**: Provide a reusable multi-line or tabular formatter for claims metadata (Customer, Tier, Product, Features, Limits, Scope, Version Bounds, Maintenance, Expiration) to standardize `license inspect` CLI subcommands across downstream binaries.

### 📊 Concurrency-Safe Usage Metering & Watermarking
- [ ] **In-Memory `UsageMeter`**: Provide a thread-safe consumption tracker against `Claims.Limits` (e.g. `meter.CanConsume("runners", n)`).
- [ ] **Watermark Tracking & Threshold Alerts**: High-watermark usage recording and configurable threshold alert callbacks (e.g., notify downstream application when usage reaches 80% or 95% of licensed capacity).

### 🔌 Framework Adapters & Middleware
- [ ] **HTTP Server Middleware**: Standard Go `func(next http.Handler) http.Handler` to extract and verify tokens, inject `Claims` into `r.Context()`, and append telemetry headers (`X-License-Status`, `X-License-Expires`).
- [ ] **gRPC Interceptors**: Provide `UnaryServerInterceptor` and `StreamServerInterceptor` for Go microservices.

### 📦 Air-Gapped & Enterprise Workflows
- [ ] **Customer Machine Fingerprint Tool**: Add `license-cli fingerprint` (or `request`) command allowing air-gapped customers to generate a clean machine/node identity bundle for license requests.
- [ ] **Offline Revocation Lists (CRL)**: Support local cryptographically signed revocation lists to invalidate compromised or leaked license IDs in air-gapped environments without network access.
- [ ] **Signed Audit & Compliance Receipts**: Offline usage snapshot generator that outputs cryptographically signed receipts to verify historical compliance during vendor audits.

### 🖥️ Built-in Fingerprint Resolvers
- [ ] Provide out-of-the-box fingerprint resolvers for:
  - AWS EC2 Instance ID & Account ID (via IMDSv2)
  - Kubernetes Cluster UID & Node Names
  - Host hardware UUID / DMI system serial

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

