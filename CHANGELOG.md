# Changelog

## [1.1.0](https://github.com/divmora/license-go/compare/v1.0.0...v1.1.0) (2026-09-18)


### Features

* **claims:** add first-class tier-to-features matrix resolution ([881b799](https://github.com/divmora/license-go/commit/881b799e984ccf52b7220eed6b5c03818ea6d6f6))


### Bug Fixes

* **scope:** auto-resolve platform identity for non-fingerprinted licenses ([#53](https://github.com/divmora/license-go/issues/53)) ([b319c0f](https://github.com/divmora/license-go/commit/b319c0fc45faf9a385355d23bb508cd0ee088cd2))
* **security:** AWS Lambda fingerprint spoofing and scope bypass via unauthenticated env vars ([#45](https://github.com/divmora/license-go/issues/45)) ([36cebb4](https://github.com/divmora/license-go/commit/36cebb4e3b944c1948fb9684dfdd53510237dd08))

## [1.0.0](https://github.com/divmora/license-go/compare/v0.7.0...v1.0.0) (2026-09-17)


### ⚠ BREAKING CHANGES

* decouple license issuance and encapsulate internal subsystems

### Features

* **claims, bsl:** runtime schema validation, simulation BSL grant override, and performance benchmarks ([c6363bf](https://github.com/divmora/license-go/commit/c6363bfcd6e46ecdbb9dfef5b8eaa93336606f20))
* **cli:** introduce domain-grouped command routing with backward-compatible shortcuts ([52db767](https://github.com/divmora/license-go/commit/52db767cca46261025ae01cbbed1589defd295ac))
* **provenance:** harden release attestation and add bi-directional build date skew ([408ab24](https://github.com/divmora/license-go/commit/408ab24d44a47b744c8c1a5161608f15dd4c7ba5))
* **security:** separate keyring maps, add fail-closed scope, and harden warn-only policy ([7002a6e](https://github.com/divmora/license-go/commit/7002a6e74a970c9aa206627fb2e1d76a71249c2d))


### Bug Fixes

* **security:** constant-time fingerprint, 128-bit key fingerprint, version segment wildcards, and parser hardening ([7901f65](https://github.com/divmora/license-go/commit/7901f65c265a3eba40540dd231ebc73ed386e70c))
* **security:** prevent symlink substitution, degraded downgrade attacks, and env spoofing ([#30](https://github.com/divmora/license-go/issues/30), [#31](https://github.com/divmora/license-go/issues/31), [#34](https://github.com/divmora/license-go/issues/34)) ([07aa117](https://github.com/divmora/license-go/commit/07aa1175d5f8eea379702061b564e189baf1df7c))
* **security:** reconcile Manager BSL conversion and expiration with clock defense ([#27](https://github.com/divmora/license-go/issues/27), [#28](https://github.com/divmora/license-go/issues/28), [#29](https://github.com/divmora/license-go/issues/29)) ([1fef733](https://github.com/divmora/license-go/commit/1fef73321f4dc9f66671649b18ce4a170c664089))
* **validator:** align clock skew tolerance with StatusAt lifecycle state reporting ([#18](https://github.com/divmora/license-go/issues/18)) ([63792bc](https://github.com/divmora/license-go/commit/63792bca7ccd39f33e2b26ca999cac5d872cea7e))
* **validator:** enforce claims.Environment when validator currentEnvironment is empty ([#16](https://github.com/divmora/license-go/issues/16)) ([88fdbfa](https://github.com/divmora/license-go/commit/88fdbfafca14853da28d2688a584a6ee5f96bd6d))
* **validator:** reject offline backward clock tampering prior to binary build date ([#17](https://github.com/divmora/license-go/issues/17)) ([d4ff4e4](https://github.com/divmora/license-go/commit/d4ff4e47d74da1887b8071f7381a8e1422ba5061))


### Code Refactoring

* decouple license issuance and encapsulate internal subsystems ([5c01ad6](https://github.com/divmora/license-go/commit/5c01ad6d1accef67a10c6d94de3bad42e950b606))

## [0.7.0](https://github.com/divmora/license-go/compare/v0.6.0...v0.7.0) (2026-09-16)


### Features

* **cli:** air-gapped license request generator and fingerprint CLI subcommands (fixes [#8](https://github.com/divmora/license-go/issues/8)) ([885844b](https://github.com/divmora/license-go/commit/885844ba3454200c478fceea29ae96a947f67faa))
* **fingerprint:** add AWS Lambda resolver and platform support ([dccd9b8](https://github.com/divmora/license-go/commit/dccd9b8f59b6ff6fdaffc08f372185af970abddc))
* **fingerprint:** AWS EC2 IMDSv2 and Kubernetes cluster fingerprint resolvers (fixes [#7](https://github.com/divmora/license-go/issues/7)) ([f424a2f](https://github.com/divmora/license-go/commit/f424a2fb180c206f79e844a224cfacd3cfe1b4dc))
* **fingerprint:** core machine identity & host hardware fingerprint engine (fixes [#6](https://github.com/divmora/license-go/issues/6)) ([cd5e539](https://github.com/divmora/license-go/commit/cd5e539a57facfade21031654a622009728010f4))
* **validator:** auto-fingerprint resolution and node-lock verification in Validator (fixes [#9](https://github.com/divmora/license-go/issues/9)) ([ce4cacd](https://github.com/divmora/license-go/commit/ce4cacd6056e93e344293fcf55b92ae7982edde5))


### Bug Fixes

* **claims:** respect minor and patch version bounds in wildcard checkMaxVersion ([#15](https://github.com/divmora/license-go/issues/15)) ([e54ce3f](https://github.com/divmora/license-go/commit/e54ce3fe6c9ca8b696c86478cca369b61af3d61d))
* **fingerprint:** prevent predictable Kubernetes cluster fingerprint collision under restricted RBAC ([#14](https://github.com/divmora/license-go/issues/14)) ([1637479](https://github.com/divmora/license-go/commit/16374796d6d12da439d46741125c68ac93f8ef01))
* **manager:** enforce license expiration in HasFeature() and CheckLimit() ([#12](https://github.com/divmora/license-go/issues/12)) ([fe58bfc](https://github.com/divmora/license-go/commit/fe58bfc2e020e2a8fa569db3bd2039c2775126ac))
* **provenance:** treat placeholder values like "none" or "dev" as Attested: false in EvaluateProvenance ([#21](https://github.com/divmora/license-go/issues/21)) ([d9dbbc6](https://github.com/divmora/license-go/commit/d9dbbc69ef567234c53be000a8319bd83e20d1ef))
* **scope:** prevent slash-spanning wildcard match in matchFeaturePattern() ([#13](https://github.com/divmora/license-go/issues/13)) ([12d50c7](https://github.com/divmora/license-go/commit/12d50c79ddb2248d117551dd74b78c7221e5cc87))
* **security:** prevent public key trust root spoofing via environment variables ([#11](https://github.com/divmora/license-go/issues/11)) ([6fb4d0d](https://github.com/divmora/license-go/commit/6fb4d0d550e7668af2d57cc88bd35615fe5281ac))

## [0.6.0](https://github.com/divmora/license-go/compare/v0.5.0...v0.6.0) (2026-09-16)


### Features

* add BSL 1.1 Additional Use Grant evaluator and bsl-eval CLI command ([b884de0](https://github.com/divmora/license-go/commit/b884de00a2c1770ecf95f8ac3f009864ba16fb40))
* add cryptographic release attestation and provenance engine ([fe37115](https://github.com/divmora/license-go/commit/fe37115d2a2bc40f4352611d19fd53400260e003))
* add standardized CLI license status formatter and license-cli status command ([55bf0e8](https://github.com/divmora/license-go/commit/55bf0e83fb36ef7b3cc124caf7a160eda9bce515))

## [0.5.0](https://github.com/divmora/license-go/compare/v0.4.0...v0.5.0) (2026-09-16)


### Features

* add authoritative server time attestation and clock skew defense ([fc65848](https://github.com/divmora/license-go/commit/fc65848c4e502c20ef15c55b4054a055b21ee7ff))
* add custom scope CLI flags to license-cli issue and verify ([e4956f3](https://github.com/divmora/license-go/commit/e4956f370855e078b5c9fdcb2d7b91208100d288))
* add diagnostic human status message (VerificationResult.StatusMessage) ([f4d4ea5](https://github.com/divmora/license-go/commit/f4d4ea5c3a633509a6c5fb9959cd0fb06998830b))
* add hierarchical namespace and group tree scope matching for Scope.Namespaces ([5a1bcf5](https://github.com/divmora/license-go/commit/5a1bcf55a7a4ba0bf3caed4af7d016f5902cc40c))
* add host URL normalization and apex domain matching for Scope.Hosts ([96f10b3](https://github.com/divmora/license-go/commit/96f10b342493e0552670f2536b5f2a6fd0c0fd63))
* add KeyRing & public key environment resolver with programmatic overrides and CLI support ([4fa9a87](https://github.com/divmora/license-go/commit/4fa9a872e71320ec100f4bf8b7f9a0e9f053ebaf))
* add reusable terminal claims inspection formatter (Claims.FormatInspect) ([3fad97d](https://github.com/divmora/license-go/commit/3fad97debc6df6b2451155daf4eef0cd79aeccf6))


### Bug Fixes

* **lint:** resolve gosimple warnings in claims and ensure golangci-lint path discovery ([1c843aa](https://github.com/divmora/license-go/commit/1c843aa932d6f82d3540904dcd0081e8252655b6))

## [0.4.0](https://github.com/divmora/license-go/compare/v0.3.0...v0.4.0) (2026-09-16)


### Features

* add BSL 1.1 change date conversion and authoritative clock skew defense ([25f1bdd](https://github.com/divmora/license-go/commit/25f1bdd7def5abaf50f0a364a6d81e127093f3bf))
* implement configurable enforcement policies and graceful degradation in manager ([4ce5a90](https://github.com/divmora/license-go/commit/4ce5a9025b572d883fea6775529f34b9d702a6a1))

## [0.3.0](https://github.com/divmora/license-go/compare/v0.2.0...v0.3.0) (2026-09-16)


### Features

* add software version locking and maintenance cutoff for perpetual licenses ([5e1e3b1](https://github.com/divmora/license-go/commit/5e1e3b12484727f761d3336c82c8e4c6e16f894d))
* implement KeyRing multi-key rotation, bundle management, and revocation ([aea738b](https://github.com/divmora/license-go/commit/aea738be190c50f23c2d4845cb7b9ebe6d6abcd0))

## [0.2.0](https://github.com/divmora/license-go/compare/v0.1.0...v0.2.0) (2026-09-16)


### Features

* initialize license-go package and CLI toolkit ([c8dc7eb](https://github.com/divmora/license-go/commit/c8dc7eb27c35d18f233ccce688e510afd441e464))
