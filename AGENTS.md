# AGENTS.md

Guidelines and operational runbooks for AI coding agents working on `github.com/divmora/license-go`.

---

## 1. Project Architecture Layout

```
license-go/
├── pkg/
│   └── license/                # Reusable Go licensing consumer SDK
│       ├── claims.go           # Standard Claims schema & evaluation helper methods
│       ├── errors.go           # Typed sentinel errors & structured error types
│       ├── keys.go             # Public Ed25519 key loading & PKIX PEM parsing
│       ├── envelope.go         # Token parsing, unmarshaling & armored PEM block unwrapping
│       ├── keyring.go          # KeyRing multi-key rotation, bundle management & revocation
│       ├── bsl.go              # BSL 1.1 Change Date, Apache 2.0 conversion & clock defense
│       ├── validator.go              # Validator struct, options, VerificationResult & accessors
│       ├── validator_constructors.go # Constructor variants (NewValidator*) & key resolution
│       ├── validator_clock.go        # Authoritative time, clock skew & tampering defense
│       ├── validator_steps.go        # 10-step pipeline orchestration (Verify*, claims, scope)
│       ├── provenance.go       # Cryptographic release attestation & binary provenance engine
│       ├── status_formatter.go # Standardized CLI status card & quota utilization formatter
│       ├── manager.go          # Daemon background monitor, file watcher, expiry alerts
│       ├── fingerprint.go      # Node/cluster fingerprint aliases & evaluation
│       ├── resolvers.go        # Infrastructure fingerprint resolvers
│       ├── keys_test.go        # Key generation & PEM round-trip tests
│       ├── keyring_test.go     # KeyRing rotation, revocation & multi-key tests
│       ├── bsl_test.go         # BSL 1.1 conversion & clock tampering defense tests
│       ├── license_test.go     # Signing, verification, tampering, expiration tests
│       ├── provenance_test.go  # Release attestation & binary checksum verification tests
│       ├── status_formatter_test.go # Status banner & quota table tests
│       ├── manager_test.go     # Background daemon lifecycle & hot-reloading tests
│       ├── policy_test.go      # Operational policy modes (Strict, Degraded, WarnOnly) tests
│       └── version_test.go     # Perpetual license version lock & maintenance cutoff tests
├── internal/
│   ├── helpers/                # String manipulation, semver, crypto matching, env & file I/O
│   ├── envelope/               # Token packing/unpacking and PEM armoring primitives
│   ├── schema/                 # JSON claims validation & required field assertions
│   ├── resolvers/              # Platform fingerprint resolvers (Host, EC2, Lambda, K8s, Container)
│   └── issuer/                 # Restricted private key generation, PEM I/O, and signing engine
├── cmd/
│   └── license-cli/            # Standalone CLI binary & subcommands
│       ├── main.go             # Entry point & subcommand dispatcher
│       ├── shared.go           # CLI parsing helpers
│       ├── cmd_keygen.go       # keygen subcommand
│       ├── cmd_keyring.go      # keyring subcommand
│       ├── cmd_issue.go        # issue subcommand
│       ├── cmd_verify.go       # verify subcommand
│       ├── cmd_inspect.go      # inspect subcommand
│       ├── cmd_status.go       # status subcommand
│       ├── cmd_bsl_eval.go     # bsl-eval subcommand
│       ├── cmd_sign_release.go # sign-release subcommand
│       ├── cmd_verify_release.go # verify-release subcommand
│       ├── cmd_inspect_release.go # inspect-release subcommand
│       ├── cmd_fingerprint.go  # fingerprint subcommand
│       └── cmd_request.go      # request subcommand
├── Makefile                    # Standardized build and test targets
└── .agents/
    └── skills/                 # Antigravity skill definitions
```

---

## 2. Safety & Cryptographic Integrity Guarantees

- **Zero External Crypto Dependencies**: The package relies purely on Go's standard library (`crypto/ed25519`, `crypto/rand`, `crypto/x509`, `encoding/pem`). Do not introduce CGo or third-party cryptographic dependencies.
- **Asymmetric Security**: Private keys must never be committed to source code or embedded into client libraries. Only the public key may be distributed with or embedded into consuming services.
- **Strict Verification Order**: Any modifications to verification must maintain the strict security sequence:
  0. Release attestation and build provenance evaluation (`EvaluateProvenance`): verify binary build authenticity and anchor authoritative BSL release date
  1. Authoritative reference time check (`WithAuthoritativeTime` / `WithServerTimeAttestation`) to detect forward clock tampering
  2. BSL 1.1 Change Date check (`BSLPolicy`): if converted, grant open-source entitlements
  3. Token unpacking and format assertion
  4. Cryptographic signature verification against KeyRing with canonical data `DIV1.<payloadB64>`
  5. JSON payload unmarshaling
  6. Product identity match
  7. Machine/cluster fingerprint match (if applicable)
  8. NotBefore & Expiration checks (accounting for clock skew and grace periods)
  9. Scope constraints check (environments, accounts, regions, clusters, namespaces, hosts)
  10. Version constraints check (`MaxVersion` / `AllowedVersions`) and maintenance cutoff (`MaintenanceExpiresAt`)

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
- **Deduplication with GitHub Issues**: If an active GitHub Issue already exists or is explicitly created for a feature, bug fix, or task, **do not duplicate it in `ROADMAP.md`**. GitHub Issues track active, assigned, or triaged tasks, while `ROADMAP.md` captures high-level, unassigned architectural vision and backlog capabilities.
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
