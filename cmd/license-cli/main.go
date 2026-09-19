package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	// Domain command groups
	case "license", "lic":
		return dispatchLicense(subArgs)
	case "release", "rel":
		return dispatchRelease(subArgs)
	case "key", "keys":
		return dispatchKey(subArgs)
	case "bsl":
		return dispatchBSL(subArgs)
	case "crl":
		return dispatchCRL(subArgs)

	// Standalone utility commands
	case "fingerprint":
		return runFingerprint(subArgs)

	// Flat backward-compatible shortcuts
	case "issue":
		return runIssue(subArgs)
	case "verify":
		return runVerify(subArgs)
	case "inspect":
		return runInspect(subArgs)
	case "status":
		return runStatus(subArgs)
	case "request":
		return runRequest(subArgs)
	case "keygen":
		return runKeygen(subArgs)
	case "keyring":
		return runKeyring(subArgs)
	case "sign-release":
		return runSignRelease(subArgs)
	case "verify-release":
		return runVerifyRelease(subArgs)
	case "inspect-release":
		return runInspectRelease(subArgs)
	case "bsl-eval":
		return runBSLEval(subArgs)
	case "sign-crl":
		return runSignCRL(subArgs)
	case "verify-crl":
		return runVerifyCRL(subArgs)
	case "inspect-crl":
		return runInspectCRL(subArgs)
	case "check-crl":
		return runCheckCRL(subArgs)
	case "sync-crl":
		return runSyncCRL(subArgs)

	// Global help
	case "help", "-h", "--help", "-help":
		printUsage()
		return nil

	default:
		fmt.Fprintf(os.Stderr, "Unknown command or group %q\n\n", cmd)
		printUsage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func dispatchLicense(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		printLicenseUsage()
		return nil
	}
	subcmd := args[0]
	subArgs := args[1:]
	switch subcmd {
	case "issue":
		return runIssue(subArgs)
	case "verify":
		return runVerify(subArgs)
	case "inspect":
		return runInspect(subArgs)
	case "status":
		return runStatus(subArgs)
	case "request":
		return runRequest(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown license command %q\n\n", subcmd)
		printLicenseUsage()
		return fmt.Errorf("unknown license command %q", subcmd)
	}
}

func dispatchRelease(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		printReleaseUsage()
		return nil
	}
	subcmd := args[0]
	subArgs := args[1:]
	switch subcmd {
	case "sign", "sign-release":
		return runSignRelease(subArgs)
	case "verify", "verify-release":
		return runVerifyRelease(subArgs)
	case "inspect", "inspect-release":
		return runInspectRelease(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown release command %q\n\n", subcmd)
		printReleaseUsage()
		return fmt.Errorf("unknown release command %q", subcmd)
	}
}

func dispatchKey(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		printKeyUsage()
		return nil
	}
	subcmd := args[0]
	subArgs := args[1:]
	switch subcmd {
	case "gen", "generate", "keygen":
		return runKeygen(subArgs)
	case "inspect", "ring", "keyring":
		return runKeyring(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown key command %q\n\n", subcmd)
		printKeyUsage()
		return fmt.Errorf("unknown key command %q", subcmd)
	}
}

func dispatchBSL(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		printBSLUsage()
		return nil
	}
	subcmd := args[0]
	subArgs := args[1:]
	switch subcmd {
	case "eval", "evaluate", "bsl-eval":
		return runBSLEval(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown bsl command %q\n\n", subcmd)
		printBSLUsage()
		return fmt.Errorf("unknown bsl command %q", subcmd)
	}
}

func dispatchCRL(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		printCRLUsage()
		return nil
	}
	subcmd := args[0]
	subArgs := args[1:]
	switch subcmd {
	case "sign", "sign-crl":
		return runSignCRL(subArgs)
	case "verify", "verify-crl":
		return runVerifyCRL(subArgs)
	case "inspect", "inspect-crl":
		return runInspectCRL(subArgs)
	case "check", "check-crl":
		return runCheckCRL(subArgs)
	case "sync", "sync-crl":
		return runSyncCRL(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown crl command %q\n\n", subcmd)
		printCRLUsage()
		return fmt.Errorf("unknown crl command %q", subcmd)
	}
}

func isHelp(s string) bool {
	return s == "help" || s == "-h" || s == "--help" || s == "-help"
}

func printUsage() {
	fmt.Println(`license-cli - Divmora software licensing toolkit

Usage:
  license-cli <group> <command> [arguments]
  license-cli <shortcut> [arguments]

Command Groups:
  license         Commercial license issuance, verification, inspection, and status
    issue           Issue and sign a new software license
    verify          Verify a license signature and evaluate its claims
    inspect         Decode and inspect license claims without verification
    status          Display standardized license status card and quota table
    request         Generate air-gapped license request (.divreq) for offline nodes

  release         Binary release attestation and provenance (DIVREL1)
    sign            Mint a cryptographic release attestation token (DIVREL1)
    verify          Verify binary release attestation and SHA-256 checksum
    inspect         Decode and inspect release attestation claims

  key             Ed25519 key pair generation and KeyRing bundle management
    gen             Generate a new Ed25519 private/public keypair
    inspect         Inspect public keys inside a PEM bundle file

  bsl             Business Source License (BSL 1.1) entitlement and conversion
    eval            Evaluate BSL 1.1 dual-licensing entitlement and Additional Use Grants

  crl             Certificate Revocation Lists (CRL) for air-gapped license invalidation
    sign            Mint and sign a new Certificate Revocation List (DIVCRL1)
    verify          Verify CRL signature and validity against trusted KeyRing
    inspect         Decode and inspect revoked license IDs and metadata
    check           Check whether a specific license ID is revoked in a CRL

Utility Commands:
  fingerprint     Inspect deterministic machine/cluster hardware fingerprint

Common Shortcuts (Backward-Compatible):
  issue, verify, inspect, status, request, keygen, keyring,
  sign-release, verify-release, inspect-release, bsl-eval,
  sign-crl, verify-crl, inspect-crl, check-crl

Use "license-cli <group> -help" or "license-cli <command> -help" for more information.`)
}

func printLicenseUsage() {
	fmt.Println(`license-cli license - Commercial license issuance, verification, inspection, and status

Usage:
  license-cli license <command> [arguments]

Available Commands:
  issue           Issue and sign a new software license
  verify          Verify a license signature and evaluate its claims
  inspect         Decode and inspect license claims without verification
  status          Display standardized license status card and quota table
  request         Generate air-gapped license request (.divreq) for offline nodes

Use "license-cli license <command> -help" for more information about a command.`)
}

func printReleaseUsage() {
	fmt.Println(`license-cli release - Binary release attestation and provenance (DIVREL1)

Usage:
  license-cli release <command> [arguments]

Available Commands:
  sign            Mint a cryptographic release attestation token (DIVREL1)
  verify          Verify binary release attestation and SHA-256 checksum
  inspect         Decode and inspect release attestation claims

Use "license-cli release <command> -help" for more information about a command.`)
}

func printKeyUsage() {
	fmt.Println(`license-cli key - Ed25519 key pair generation and KeyRing bundle management

Usage:
  license-cli key <command> [arguments]

Available Commands:
  gen             Generate a new Ed25519 private/public keypair
  inspect         Inspect public keys inside a PEM bundle file

Use "license-cli key <command> -help" for more information about a command.`)
}

func printBSLUsage() {
	fmt.Println(`license-cli bsl - Business Source License (BSL 1.1) entitlement and conversion

Usage:
  license-cli bsl <command> [arguments]

Available Commands:
  eval            Evaluate BSL 1.1 dual-licensing entitlement and Additional Use Grants

Use "license-cli bsl <command> -help" for more information about a command.`)
}

func printCRLUsage() {
	fmt.Println(`license-cli crl - Certificate Revocation Lists (CRL) for air-gapped license invalidation

Usage:
  license-cli crl <command> [arguments]

Available Commands:
  sign            Mint and sign a new Certificate Revocation List (DIVCRL1)
  verify          Verify CRL signature and validity against trusted KeyRing
  inspect         Decode and inspect revoked license IDs and metadata
  check           Check whether a specific license ID is revoked in a CRL
  sync            Fetch, verify, and cache CRL from a remote HTTPS endpoint

Use "license-cli crl <command> -help" for more information about a command.`)
}
