# Changelog

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
