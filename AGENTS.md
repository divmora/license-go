# AGENTS.md

Guidelines and operational runbooks for AI coding agents working on `github.com/divmora/license-go`.

---

## 1. Project Architecture Layout

```
license-go/
├── pkg/
│   └── license/                # Reusable Go licensing library
│       ├── claims.go           # Standard Claims schema & evaluation helper methods
│       ├── errors.go           # Typed sentinel errors & structured error types
│       ├── keys.go             # Ed25519 key generation, PEM PKCS#8/PKIX serialization
│       ├── envelope.go         # Token serialization (compact DIV1 & armored PEM blocks)
│       ├── keyring.go          # KeyRing multi-key rotation, bundle management & revocation
│       ├── signer.go           # License generation & signing engine (private key)
│       ├── validator.go        # Client-side verification engine (public key)
│       ├── manager.go          # Daemon background monitor, file watcher, expiry alerts
│       ├── keys_test.go        # Key generation & PEM round-trip tests
│       ├── keyring_test.go     # KeyRing rotation, revocation & multi-key tests
│       ├── license_test.go     # Signing, verification, tampering, expiration tests
│       ├── manager_test.go     # Background daemon lifecycle & hot-reloading tests
│       └── version_test.go     # Perpetual license version lock & maintenance cutoff tests
├── cmd/
│   └── license-cli/            # Standalone CLI binary (keygen, issue, verify, inspect)
│       └── main.go
├── Makefile                    # Standardized build and test targets
└── .agents/
    └── skills/                 # Antigravity skill definitions
```

---

## 2. Safety & Cryptographic Integrity Guarantees

- **Zero External Crypto Dependencies**: The package relies purely on Go's standard library (`crypto/ed25519`, `crypto/rand`, `crypto/x509`, `encoding/pem`). Do not introduce CGo or third-party cryptographic dependencies.
- **Asymmetric Security**: Private keys must never be committed to source code or embedded into client libraries. Only the public key may be distributed with or embedded into consuming services.
- **Strict Verification Order**: Any modifications to verification must maintain the strict security sequence:
  1. Token unpacking and format assertion
  2. Cryptographic signature verification against canonical data `DIV1.<payloadB64>`
  3. JSON payload unmarshaling
  4. Product identity match
  5. Machine/cluster fingerprint match (if applicable)
  6. NotBefore & Expiration checks (accounting for clock skew and grace periods)
  7. Scope constraints check (environments, accounts, regions, clusters, namespaces, hosts)
  8. Version constraints check (`MaxVersion` / `AllowedVersions`) and maintenance cutoff (`MaintenanceExpiresAt`)

---

## 3. Go Ecosystem Best Practices

- **Go Version**: Minimum Go 1.22+.
- **Standard Library First**: Prefer Go standard library over external dependencies.
- **Structured Error Handling**: Use typed sentinel errors in `errors.go` and wrap contextual errors with `%w`. Structured error types (like `*LimitExceededError`) must implement `Is(target error) bool`.
- **Testing**: Maintain high test coverage with race detector enabled (`go test -race ./...`). Ensure all file and key operations run against `t.TempDir()`.

---

## 4. Conventional Commits

All commits MUST follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` New features or capabilities
- `fix:` Bug fixes
- `docs:` Documentation changes
- `chore:` Tooling, CI/CD, dependency updates
- `refactor:` Code refactoring without behavioral change
- `test:` Adding or updating tests
- `feat!:` Breaking changes

---

## 5. Living Product Roadmap (`ROADMAP.md`)

- **Adding Tasks**: Whenever an optimization, edge case, or capability is identified during pair programming, log it in `ROADMAP.md`.
- **Pruning Tasks**: Once an item is implemented, verified with automated tests, and committed, remove it from `ROADMAP.md` immediately.

---

## 6. Verification Commands

Run these verification commands before proposing changes:

```bash
make fmt          # Format all Go source files
make test         # Run unit and integration tests
make test-race    # Run test suite with Go race detector
make lint         # Run linter
make build        # Compile license-cli binary
```
