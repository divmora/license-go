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

	subcommand := os.Args[1]
	args := os.Args[2:]

	var err error
	switch subcommand {
	case "keygen":
		err = runKeygen(args)
	case "issue":
		err = runIssue(args)
	case "verify":
		err = runVerify(args)
	case "inspect":
		err = runInspect(args)
	case "status":
		err = runStatus(args)
	case "bsl-eval":
		err = runBSLEval(args)
	case "keyring":
		err = runKeyring(args)
	case "sign-release":
		err = runSignRelease(args)
	case "verify-release":
		err = runVerifyRelease(args)
	case "inspect-release":
		err = runInspectRelease(args)
	case "fingerprint":
		err = runFingerprint(args)
	case "request":
		err = runRequest(args)
	case "help", "-h", "--help", "-help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand %q\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`license-cli - Divmora software licensing toolkit

Usage:
  license-cli <command> [arguments]

Available Commands:
  keygen          Generate a new Ed25519 private/public keypair
  issue           Issue and sign a new software license
  verify          Verify a license signature and evaluate its claims
  status          Display standardized license status card and quota table
  bsl-eval        Evaluate BSL 1.1 dual-licensing entitlement and Additional Use Grants
  inspect         Decode and inspect license claims without verification
  keyring         Inspect public keys inside a PEM bundle file
  sign-release    Mint a cryptographic release attestation token (DIVREL1)
  verify-release  Verify binary release attestation and SHA-256 checksum
  inspect-release Decode and inspect release attestation claims
  fingerprint     Inspect deterministic machine/cluster hardware fingerprint
  request         Generate air-gapped license request (.divreq) for offline nodes
  help            Display help information

Use "license-cli <command> -help" for more information about a command.`)
}
