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
