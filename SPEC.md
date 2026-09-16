# Divmora License Protocol Specification (DIV1)

- **Document Version**: 1.1.0
- **Protocol Identifier**: `DIV1`
- **Status**: Stable / Standard RFC
- **Authors**: Divmora Engineering Team (<engineering@divmora.com>)
- **Repository**: [github.com/divmora/license-go](https://github.com/divmora/license-go)

---

## Abstract

This document defines the **Divmora License Protocol (`DIV1`)**, an enterprise-grade, cryptographically secure software licensing format and evaluation standard. `DIV1` provides asymmetric digital signatures using Ed25519, compact single-line and armored PEM serialization formats, hierarchical infrastructure scoping, perpetual license version locking, Business Source License (BSL 1.1) autonomous open-source conversion, authoritative clock tampering defense, and multi-key rotation and revocation semantics.

---

## Table of Contents

1. [Architecture & Design Principles](#1-architecture--design-principles)
2. [Cryptographic Specifications](#2-cryptographic-specifications)
   - [2.1 Algorithm & Curves](#21-algorithm--curves)
   - [2.2 Key Formats & Serialization](#22-key-formats--serialization)
   - [2.3 Key Identifiers (`kid`) & Fingerprints](#23-key-identifiers-kid--fingerprints)
   - [2.4 Multi-Key Ring & Lifecycle States](#24-multi-key-ring--lifecycle-states)
3. [Token Envelope & Wire Formats](#3-token-envelope--wire-formats)
   - [3.1 Compact Token Format](#31-compact-token-format)
   - [3.2 Armored PEM Format](#32-armored-pem-format)
   - [3.3 Canonical Signed Data](#33-canonical-signed-data)
4. [Claims Schema Specification](#4-claims-schema-specification)
   - [4.1 JSON Schema](#41-json-schema)
   - [4.2 Field Definitions & Constraints](#42-field-definitions--constraints)
   - [4.3 Infrastructure Scoping (`Scope`)](#43-infrastructure-scoping-scope)
5. [Business Source License (BSL 1.1) Semantics](#5-business-source-license-bsl-11-semantics)
   - [5.1 Dual-Lifecycle State Machine](#51-dual-lifecycle-state-machine)
   - [5.2 Clock Tampering Defense](#52-clock-tampering-defense)
6. [Operational Enforcement Policies](#6-operational-enforcement-policies)
   - [6.1 Policy Modes](#61-policy-modes)
   - [6.2 Grace Period Dynamics](#62-grace-period-dynamics)
   - [6.3 Read-Only Degradation](#63-read-only-degradation)
7. [Strict Verification Algorithm](#7-strict-verification-algorithm)
   - [7.1 Verification Flowchart](#71-verification-flowchart)
   - [7.2 Step-by-Step Security Pipeline](#72-step-by-step-security-pipeline)
8. [Standard Error Codes & Failure Modes](#8-standard-error-codes--failure-modes)
9. [Cross-Language Interoperability Guidelines](#9-cross-language-interoperability-guidelines)

---

## 1. Architecture & Design Principles

The `DIV1` licensing architecture is engineered around the following core tenets:

1. **Zero External Cryptographic Dependencies**: All core cryptographic verification must rely strictly on standard system libraries (`RFC 8032` Ed25519) without requiring external CGo or third-party crypto modules.
2. **Strict Asymmetric Separation**: Private keys are held exclusively by the software vendor or automated CI/CD licensing portal (e.g. via KMS or Vault). Consuming software binaries and client containers only bundle public verification keys.
3. **Canonical Data Binding**: Digital signatures sign canonical ASCII strings that explicitly prefix the protocol envelope version (`DIV1.`), preventing cross-protocol substitution or signature-stripping attacks.
4. **Resilience to Network Partitions**: Licenses are completely self-contained and verifiable offline in air-gapped environments without requiring runtime network calls to a licensing server.
5. **Deterministic Evaluation Order**: Verification steps must execute in a strictly defined chronological order, rejecting tampered or invalid states before evaluating deeper entitlements.

---

## 2. Cryptographic Specifications

### 2.1 Algorithm & Curves

All digital signatures in the `DIV1` protocol MUST use **Ed25519** (Edwards-curve Digital Signature Algorithm) as specified in **RFC 8032 (PureEd25519)**:

- **Curve**: Curve25519 ($y^2 = x^3 + 486662x^2 + x$ over $\mathbb{F}_{2^{255}-19}$)
- **Hash Function**: SHA-512 ($H(m)$)
- **Public Key Length**: 32 bytes (256 bits)
- **Private Key Seed Length**: 32 bytes (expanded to 64 bytes)
- **Signature Length**: 64 bytes (512 bits, composed of $R \parallel S$)

### 2.2 Key Formats & Serialization

Public and private keys are serialized using standard ASN.1 DER encodings encapsulated in PEM blocks:

- **Public Keys**: Serialized according to **PKIX SubjectPublicKeyInfo** (`RFC 5280`, `RFC 8410`):
  ```
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEA...
  -----END PUBLIC KEY-----
  ```
- **Private Keys**: Serialized according to **PKCS#8 PrivateKeyInfo** (`RFC 5208`, `RFC 8410`):
  ```
  -----BEGIN PRIVATE KEY-----
  MC4CAQAwBQYDK2VwBCIEI...
  -----END PRIVATE KEY-----
  ```

### 2.3 Key Identifiers (`kid`) & Fingerprints

- **Key ID (`kid`)**: A string identifier associated with a signing key. It may be a human-readable slug (e.g., `divmora-root-2026`), a UUID v4, or the key fingerprint.
- **Key Fingerprint**: The canonical fingerprint of an Ed25519 public key is defined as the SHA-256 hash of its raw 32-byte public key representation, formatted as an uppercase hexadecimal string:
  $$\text{Fingerprint} = \text{Hex}(\text{SHA-256}(\text{RawPublicKey}_{32}))$$
  Example: `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`

### 2.4 Multi-Key Ring & Lifecycle States

A `KeyRing` manages a collection of public verification keys. Each key in the ring resides in one of three lifecycle states:

```
               ┌───────────────┐
               │    ACTIVE     │◄── Primary key used for active verification
               └───────┬───────┘
                       │
                       │ (Key Rotation)
                       ▼
               ┌───────────────┐
               │   RETIRING    │◄── Verifies existing licenses; phase-out
               └───────┬───────┘
                       │
                       │ (Revocation / Incident Response)
                       ▼
               ┌───────────────┐
               │    REVOKED    │◄── Rejects all signatures with ErrKeyRevoked
               └───────────────┘
```

1. **`ACTIVE`**: The key is trusted and current. The primary active key is selected when verifying licenses without a specific `kid`.
2. **`RETIRING`**: The key is valid for verifying existing, unexpired licenses, but should not be used for issuing new licenses.
3. **`REVOKED`**: The key has been compromised or retired. Verification against a revoked key MUST fail immediately with `ErrKeyRevoked`, bypassing signature evaluation.

Multi-key bundles are serialized into a single `.pem` file by concatenating consecutive PEM `PUBLIC KEY` blocks.

---

## 3. Token Envelope & Wire Formats

### 3.1 Compact Token Format

A compact `DIV1` license token is a single dot-delimited (`.`) ASCII string composed of three distinct segments:

$$\text{Token} = \text{DIV1} \mathbin{.} \text{PayloadB64} \mathbin{.} \text{SignatureB64}$$

```
DIV1.eyJpZCI6ImxpYy0xMjM... .Gz7wQ6sP...
├───┘ ├───────────────────┘  ├──────────┘
│     │                      └─ Segment 3: RawURLEncode(Ed25519 Signature, 64 bytes)
│     └──────────────────────── Segment 2: RawURLEncode(JSON Claims Payload)
└────────────────────────────── Segment 1: Protocol Header ("DIV1")
```

1. **Segment 1 (Protocol Header)**: Exactly the four ASCII characters `DIV1`.
2. **Segment 2 (Payload)**: The UTF-8 JSON claims payload, encoded using **Base64URL without padding** (`RFC 4648 §5`).
3. **Segment 3 (Signature)**: The 64-byte Ed25519 digital signature, encoded using **Base64URL without padding** (`RFC 4648 §5`).

### 3.2 Armored PEM Format

For distribution via email, config maps, or support tickets, tokens may be formatted as an armored PEM block:

```
-----BEGIN DIVMORA LICENSE KEY-----
DIV1.eyJpZCI6ImxpYy0wMDEiLCJjdXN0b21lciI6eyJuYW1lIjoiQWNtZSBDb3Jw
IiwiZW1haWwiOiJhZG1pbkBhY21lLmNvbSJ9LCJwcm9kdWN0IjoiZ2l0bGFiLWZs
ZWV0LWdvdmVybm9yIiwicGxhbiI6ImVudGVycHJpc2UiLCJpc3N1ZWRfYXQiOiIy
MDI2LTA5LTE2VDAwOjAwOjAwWiJ9.X8bZ3...
-----END DIVMORA LICENSE KEY-----
```

- **Header Marker**: `-----BEGIN DIVMORA LICENSE KEY-----`
- **Footer Marker**: `-----END DIVMORA LICENSE KEY-----`
- **Line Length**: The compact token string is wrapped every 64 characters with a newline (`\n` or `\r\n`).

### 3.3 Canonical Signed Data

To prevent cross-protocol splicing attacks and ensure envelope authenticity, the message passed to the Ed25519 signing and verification functions is the canonical byte string:

$$M_{\text{signed}} = \text{"DIV1."} \mathbin{\Vert} \text{PayloadB64}$$

Where `PayloadB64` is the exact Base64URL-encoded representation of the JSON payload.

---

## 4. Claims Schema Specification

### 4.1 JSON Schema

All `DIV1` licenses unpack to a JSON object adhering to the following schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "DivmoraLicenseClaims",
  "type": "object",
  "required": ["id", "customer", "product", "plan", "issued_at"],
  "properties": {
    "id": { "type": "string", "format": "uuid" },
    "kid": { "type": "string" },
    "customer": {
      "type": "object",
      "required": ["name"],
      "properties": {
        "name": { "type": "string" },
        "email": { "type": "string", "format": "email" },
        "org_id": { "type": "string" }
      }
    },
    "product": { "type": "string" },
    "plan": { "type": "string" },
    "issued_at": { "type": "string", "format": "date-time" },
    "not_before": { "type": "string", "format": "date-time" },
    "expires_at": { "type": "string", "format": "date-time" },
    "grace_period_days": { "type": "integer", "minimum": 0 },
    "features": {
      "type": "array",
      "items": { "type": "string" }
    },
    "limits": {
      "type": "object",
      "additionalProperties": { "type": "integer" }
    },
    "scope": { "$ref": "#/$defs/Scope" },
    "environment": { "type": "string" },
    "fingerprint": { "type": "string" },
    "max_version": { "type": "string" },
    "allowed_versions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "maintenance_expires_at": { "type": "string", "format": "date-time" },
    "metadata": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    }
  },
  "$defs": {
    "Scope": {
      "type": "object",
      "properties": {
        "environments": { "type": "array", "items": { "type": "string" } },
        "accounts": { "type": "array", "items": { "type": "string" } },
        "regions": { "type": "array", "items": { "type": "string" } },
        "clusters": { "type": "array", "items": { "type": "string" } },
        "namespaces": { "type": "array", "items": { "type": "string" } },
        "hosts": { "type": "array", "items": { "type": "string" } },
        "custom": {
          "type": "object",
          "additionalProperties": { "type": "array", "items": { "type": "string" } }
        }
      }
    }
  }
}
```

### 4.2 Field Definitions & Constraints

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `id` | `string` | **Yes** | Unique identifier (UUID v4) for tracking, auditing, and revocation. |
| `kid` | `string` | No | Identifier or fingerprint of the signing key. |
| `customer.name` | `string` | **Yes** | Legal entity or licensee name. |
| `customer.email` | `string` | No | Primary technical contact or billing email. |
| `customer.org_id` | `string` | No | Multi-tenant organization or account ID. |
| `product` | `string` | **Yes** | Product name (e.g., `gitlab-fleet-governor`), suite (`divmora-suite`), comma-separated list, or wildcard (`*`). |
| `plan` | `string` | **Yes** | License tier: `community`, `starter`, `pro`, `enterprise`, `trial`. |
| `issued_at` | `RFC3339` | **Yes** | Timestamp when the license was minted. |
| `not_before` | `RFC3339` | No | Earliest valid timestamp. Evaluation prior to this time returns `ErrNotYetValid`. |
| `expires_at` | `RFC3339` | No | Expiration timestamp. Omission or zero-value indicates a **perpetual** license. |
| `grace_period_days`| `integer` | No | Operational buffer days allowed after `expires_at`. |
| `features` | `[]string`| No | Entitlement flags. Supports exact tokens, wildcard (`*`), and glob patterns (`ha.*`). |
| `limits` | `map[string]int64`| No | Capacity limits. A limit value of `-1` denotes unlimited capacity. |
| `fingerprint` | `string` | No | Machine, EC2, or cluster identity binding. |
| `max_version` | `string` | No | Maximum authorized SemVer bound (e.g. `1.*`, `<=2.5.0`) for perpetual licenses. |
| `allowed_versions`| `[]string`| No | Explicit allowlist of SemVer version globs (e.g. `["1.*", "2.0.*"]`). |
| `maintenance_expires_at`| `RFC3339`| No | Cutoff date for software upgrades. Releases built after this date return `ErrMaintenanceExpired`. |
| `metadata` | `map[string]string`| No | Arbitrary custom metadata key-value pairs. |

### 4.3 Infrastructure Scoping (`Scope`)

The `scope` block restricts authorized deployment boundaries. An empty or omitted dimension permits all values:

```json
"scope": {
  "environments": ["production", "staging"],
  "accounts": ["123456789012"],
  "regions": ["us-east-1", "eu-west-*"],
  "clusters": ["k8s-prod-us-east-1a"],
  "namespaces": ["divmora/*", "acme-corp/secops"],
  "hosts": ["*.divmora.internal", "runner-01.acme.corp"],
  "custom": {
    "tier": ["pci-dss", "hipaa"]
  }
}
```

---

## 5. Business Source License (BSL 1.1) Semantics

### 5.1 Dual-Lifecycle State Machine

Software published under the Business Source License 1.1 operates in a dual-lifecycle state:

```
        ┌────────────────────────────────────────────────────────┐
        │  Release Date: T0                                      │
        │  Governing License: BSL-1.1                            │
        │  Commercial License Required: YES                      │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    │ (Change Period Elapsed: default 3 years)
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │  Change Date: T0 + 3 Years                             │
        │  Governing License: Apache-2.0 (Open Source)           │
        │  Commercial License Required: NO (Unrestricted Bypass) │
        └────────────────────────────────────────────────────────┘
```

1. **Before Change Date**: The software is source-available under BSL 1.1. Commercial tokens are strictly verified. If a license is missing or expired, execution is halted or degraded per policy.
2. **On or After Change Date**: The software automatically converts to its open-source Change License (default: **Apache-2.0**). The verification engine automatically generates synthetic community claims (`Plan: "open-source"`, `Features: ["*"]`), permitting unrestricted execution even if no license key or file exists.

### 5.2 Clock Tampering Defense

To defend against forward system clock manipulation (e.g., advancing the host system clock by 3 years to prematurely trigger Apache-2.0 open-source conversion):

1. Consuming applications provide an authoritative reference time (e.g., fetched from external API HTTP `Date` headers, cloud metadata, or NTP).
2. The validator compares `localUTC` and `authoritativeUTC`:
   $$\text{Tampered} = \text{BSLPolicy.IsConverted}(\text{localUTC}) \land \neg \text{BSLPolicy.IsConverted}(\text{authoritativeUTC})$$
3. If tampering is detected:
   - The validator anchors the evaluation reference time to `authoritativeUTC`.
   - Sets `ClockTampered: true` on `VerificationResult`.
   - Strictly enforces the commercial license, rejecting missing or invalid tokens.

---

## 6. Operational Enforcement Policies

### 6.1 Policy Modes

The background daemon manager (`Manager`) enforces one of three operational policy modes:

| Policy Mode | Expiration / Error Behavior | Features & Limits | Use Case |
| :--- | :--- | :--- | :--- |
| `PolicyStrict` | **Fails closed**. Halts operations immediately. | Denies unentitled features; fails limits. | Zero-tolerance financial / compliance deployments. |
| `PolicyDegraded` | **Fails open safely**. Falls back to `FallbackClaims` or community tier. | Features/limits degraded to free tier. Read-only mode optionally enforced. | High-availability CI/CD pipelines (e.g. `gitlab-fleet-governor`). |
| `PolicyWarnOnly` | **Non-blocking audit**. Permits execution unconditionally while logging errors. | Wildcard features permitted; limits ignored. | Pre-enforcement trials and dry-run migrations. |

### 6.2 Grace Period Dynamics

When a license expires, it enters a grace period window if `grace_period_days > 0`:

$$\text{EffectiveExpiry} = \text{ExpiresAt} + (\text{grace\_period\_days} \times 24 \text{ hours})$$

- $\text{Now} \le \text{ExpiresAt}$: `StatusActive`.
- $\text{ExpiresAt} < \text{Now} \le \text{EffectiveExpiry}$: `StatusGracePeriod`. The license continues to operate, but warnings are emitted.
- $\text{Now} > \text{EffectiveExpiry}$: `StatusExpired`. Operations halt or degrade per policy.

### 6.3 Read-Only Degradation

Under `PolicyDegraded`, when `DegradedReadOnly: true` is configured:
- Read and status endpoints continue functioning.
- Mutation and write operations calling `CanMutate()` return `ErrDegradedReadOnly` to prevent operational corruption while keeping monitoring systems healthy.

---

## 7. Strict Verification Algorithm

### 7.1 Verification Flowchart

```
                          ┌───────────────────────────┐
                          │   Raw Input Token / File  │
                          └─────────────┬─────────────┘
                                        │
                      [0. Authoritative Time & Drift Check]
                                        ▼
                      [1. BSL 1.1 Change Date Conversion?]
                                 /             \
                             YES                 NO
                             /                     \
               ┌───────────────────────┐   [2. Unpack & Base64URL Decode]
               │ Synthetic Open Source │            │
               │ Apache-2.0 Entitlement│   [3. Ed25519 KeyRing Signature]
               └───────────────────────┘            │
                                           [4. Unmarshal Claims JSON]
                                                    │
                                           [5. Product Identity Match]
                                                    │
                                           [6. Node/Cluster Fingerprint]
                                                    │
                                           [7. Temporal Validity Checks]
                                                    │
                                           [8. Scope Constraints Check]
                                                    │
                                           [9. Version & Maintenance Check]
                                                    │
                                                    ▼
                                       ┌───────────────────────────┐
                                       │  ✓ Verification Succeeded │
                                       └───────────────────────────┘
```

### 7.2 Step-by-Step Security Pipeline

Any conforming `DIV1` verification implementation MUST execute the security checks in the following sequential order:

1. **Step 0 (Authoritative Clock Verification)**: Resolve effective evaluation time. If local clock indicates BSL conversion but authoritative time does not, anchor time to authoritative time and flag clock tampering.
2. **Step 1 (BSL 1.1 Open-Source Check)**: Check if BSL Change Date has arrived. If converted, grant open-source community entitlements and bypass token requirement.
3. **Step 2 (Token Unpacking)**: Unwrap armored headers if present, split by dot (`.`), assert `DIV1` magic header, and Base64URL-decode payload and 64-byte signature.
4. **Step 3 (Cryptographic Signature Verification)**: Verify Ed25519 signature over `DIV1.<payloadB64>` against the trusted `KeyRing`. Reject immediately if the key is untrusted or marked `REVOKED`.
5. **Step 4 (JSON Payload Unmarshaling)**: Decode UTF-8 JSON claims payload.
6. **Step 5 (Product Identity Match)**: Assert `claims.Product` matches target product (supports exact match, suite match `divmora-suite`, comma-separated lists, and wildcard `*`).
7. **Step 6 (Fingerprint Binding Match)**: If `claims.Fingerprint` or validator mandates node-locking, verify machine/cluster identity.
8. **Step 7 (Temporal Validity Checks)**:
   - Check `NotBefore`: Reject if $\text{Now} < \text{NotBefore} - \text{ClockSkew}$.
   - Check `ExpiresAt`: If not perpetual, verify $\text{Now} \le \text{ExpiresAt} + \text{GracePeriod} + \text{ClockSkew}$.
9. **Step 8 (Scope Constraints Evaluation)**: Verify deployment boundaries (environments, accounts, regions, clusters, namespaces, hostnames, and custom dimensions).
10. **Step 9 (Version & Maintenance Cutoff Check)**:
    - Check `MaxVersion` and `AllowedVersions` against current running software version.
    - Check `MaintenanceExpiresAt` against current binary build timestamp.

---

## 8. Standard Error Codes & Failure Modes

Conforming implementations MUST distinguish the following typed error conditions:

| Sentinel Error | Code Identifier | Description |
| :--- | :--- | :--- |
| `ErrInvalidLicenseFormat` | `DIV_ERR_INVALID_FORMAT` | Token malformed, corrupt Base64URL, or unsupported header prefix. |
| `ErrInvalidSignature` | `DIV_ERR_INVALID_SIGNATURE` | Ed25519 cryptographic signature verification failed. |
| `ErrKeyRevoked` | `DIV_ERR_KEY_REVOKED` | Signing key is explicitly marked as revoked in KeyRing. |
| `ErrKeyNotFound` | `DIV_ERR_KEY_NOT_FOUND` | Specified `kid` was not found in trusted KeyRing. |
| `ErrMissingPublicKey` | `DIV_ERR_MISSING_KEY` | No public keys configured in KeyRing for verification. |
| `ErrExpired` | `DIV_ERR_EXPIRED` | License expiration date (and grace period) has passed. |
| `ErrNotYetValid` | `DIV_ERR_NOT_YET_VALID` | Current time is before `not_before` activation timestamp. |
| `ErrProductMismatch` | `DIV_ERR_PRODUCT_MISMATCH` | License product does not authorize this application. |
| `ErrFeatureNotEntitled`| `DIV_ERR_FEATURE_NOT_ENTITLED`| Requested feature flag is not present in entitlements list. |
| `ErrLimitExceeded` | `DIV_ERR_LIMIT_EXCEEDED` | Current usage count exceeds licensed quota limit. |
| `ErrScopeMismatch` | `DIV_ERR_SCOPE_MISMATCH` | Deployment environment, cloud account, region, or host not in scope. |
| `ErrVersionNotEntitled`| `DIV_ERR_VERSION_NOT_ENTITLED`| Running software version exceeds SemVer upper bounds. |
| `ErrMaintenanceExpired`| `DIV_ERR_MAINTENANCE_EXPIRED` | Software release date exceeds maintenance cutoff window. |
| `ErrClockTamperingDetected`| `DIV_ERR_CLOCK_TAMPERED` | Local clock advanced forward to simulate BSL conversion. |
| `ErrDegradedMode` | `DIV_ERR_DEGRADED_MODE` | Service is operating in fallback/community mode. |
| `ErrDegradedReadOnly` | `DIV_ERR_DEGRADED_READONLY` | Mutation rejected because service is in degraded read-only mode. |

---

## 9. Cross-Language Interoperability Guidelines

When implementing the `DIV1` protocol in other languages (such as TypeScript, Python, Rust, or Java):

1. **Standard Cryptography**: Use pure Ed25519 (`RFC 8032`). Do not concatenate secret key seeds or omit the public key prefix during signing.
2. **Canonical Signed String**: Always verify the signature against the ASCII bytes of `"DIV1." + payloadBase64`. Never re-serialize the JSON object before verifying signature! Re-serializing JSON introduces formatting, ordering, and whitespace discrepancies. Always verify the exact Base64URL string received on the wire.
3. **Strict SemVer Matching**: Version comparisons for `max_version` should follow standard Semantic Versioning 2.0.0 rules (e.g. `v1.2.3` stripped to `1.2.3`).
4. **Armored Unwrapping**: Strip all boundary whitespace, carriage returns (`\r`), and newlines (`\n`) prior to decoding.
