# Contributing to `license-go`

Thank you for your interest in contributing to **`license-go`**! We welcome contributions, improvements, and bug fixes from the Divmora community.

---

## 1. Prerequisites

Ensure you have the following tools installed locally:
- **Go**: Version 1.22 or higher
- **Make**: For running automated tasks
- **golangci-lint**: Version 1.55+ (for code quality and formatting checks)

---

## 2. Development & Makefile Targets

We provide standardized `make` targets for building, testing, and formatting:

```bash
# Build the license-cli executable into bin/
make build

# Run all unit and integration tests
make test

# Run tests with the Go race detector enabled
make test-race

# Generate a test coverage profile
make test-coverage

# Format all Go source code according to standard conventions
make fmt

# Run linters across the codebase
make lint

# Clean build artifacts and temporary files
make clean
```

---

## 3. Conventional Commits

All commit messages in this repository must adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification:

| Prefix | Description |
| :--- | :--- |
| `feat:` | A new user-facing capability or API feature |
| `fix:` | A bug fix |
| `docs:` | Documentation changes only |
| `chore:` | Tooling, dependencies, or repository maintenance |
| `refactor:` | Code restructuring without behavioral change |
| `test:` | Adding or updating tests |
| `feat!:` / `fix!:` | Breaking API changes (triggers semver major bump) |

Example:
```bash
git commit -m "feat(validator): add support for custom fingerprint assertions"
```

---

## 4. Submitting a Pull Request

1. Fork or branch from `main`.
2. Ensure all tests pass (`make test-race`).
3. Verify that the code is cleanly formatted (`make fmt`) and passes linting (`make lint`).
4. Submit a Pull Request targeting `main` with a clear explanation of changes and rationale.

---

## 5. Licensing of Contributions

By submitting a contribution to this repository, you agree that your contributions will be licensed under the project's **Apache License, Version 2.0**.
