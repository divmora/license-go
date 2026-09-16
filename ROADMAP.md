# Living Product Roadmap: `license-go`

This document tracks upcoming capabilities, planned optimizations, and ecosystem integrations for the Divmora licensing package and CLI.

> [!NOTE]
> In accordance with [AGENTS.md](file:///Users/ngoyal16/divmora/github-repos/license-go/AGENTS.md), items are added when identified and pruned immediately once implemented, tested, and committed.

---

## 🎯 Upcoming Capabilities

### 🔐 KMS & Vault Remote Signing
- [ ] Support AWS KMS asymmetric Ed25519 signing in `license-cli` (enabling license generation in CI/CD without exposing private key files).
- [ ] Support HashiCorp Vault Transit engine for enterprise license issuance workflows.

### 🌐 Online Activation & Revocation Checking
- [ ] Optional HTTP client middleware for periodic online heartbeat / activation checks against a centralized Divmora licensing server.
- [ ] Cryptographic Revocation List (CRL) verification to revoke compromised license IDs before expiration.

### 🖥️ Built-in Fingerprint Resolvers
- [ ] Provide out-of-the-box fingerprint resolvers for:
  - AWS EC2 Instance ID & Account ID
  - Kubernetes Cluster UID & Node Names
  - Host hardware UUID / DMI system serial

### ⚡ Performance & Streaming
- [ ] Zero-allocation validator optimizations for microservices processing high-frequency tenant licenses.
- [ ] Export Prometheus / OpenTelemetry metrics from `Manager` for license status, days remaining, and validation latency.
