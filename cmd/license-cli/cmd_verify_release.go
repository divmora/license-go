package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func runVerifyRelease(args []string) error {
	fs := flag.NewFlagSet("verify-release", flag.ExitOnError)
	pubKeyPath := fs.String("public-key", "", "Path to public key PEM or PEM bundle file (optional; falls back to DIVMORA_PUBLIC_KEY/DIVMORA_PUBLIC_KEYS_PEM)")
	attestationSource := fs.String("attestation", "", "Path to release attestation file or raw DIVREL1 token (required)")
	product := fs.String("product", "", "Expected product name to assert")
	version := fs.String("version", "", "Running binary version to assert")
	gitCommit := fs.String("git-commit", "", "Running git commit SHA to assert")
	binaryPath := fs.String("binary", "", "Path to binary executable to verify against attested SHA-256 digest")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *attestationSource == "" {
		return errors.New("attestation required: pass -attestation <file or token>")
	}

	var ring *license.KeyRing
	if *pubKeyPath != "" {
		r, err := license.ParseKeyRingFromString(*pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load public key from %s: %w", *pubKeyPath, err)
		}
		ring = r
	} else {
		resolvedKey, err := license.ResolveKeyRingWithSource()
		if err != nil {
			return fmt.Errorf("public verification key required: %w (pass -public-key or set %s / %s)", err, license.EnvPublicKey, license.EnvPublicKeysPEM)
		}
		ring = resolvedKey.KeyRing
	}

	rawToken := *attestationSource
	if data, err := os.ReadFile(*attestationSource); err == nil {
		rawToken = string(data)
	}

	params := license.ProvenanceParams{
		ExpectedProduct: *product,
		CurrentVersion:  *version,
		CurrentCommit:   *gitCommit,
		BinaryPath:      *binaryPath,
	}

	prov, err := license.EvaluateProvenance(rawToken, ring, params)
	if err != nil {
		return fmt.Errorf("RELEASE VERIFICATION FAILED: %w", err)
	}

	fmt.Println("✓ RELEASE ATTESTATION VERIFIED: Signature and release provenance are valid!")
	if prov.Claims != nil {
		fmt.Printf("Product:       %s\n", prov.Claims.Product)
		fmt.Printf("Version:       %s\n", prov.Claims.Version)
		if prov.Claims.GitCommit != "" {
			fmt.Printf("Git Commit:    %s\n", prov.Claims.GitCommit)
		}
		if !prov.Claims.BuildDate.IsZero() {
			fmt.Printf("Build Date:    %s\n", prov.Claims.BuildDate.Format(time.RFC3339))
		}
		if !prov.Claims.ReleaseDate.IsZero() {
			fmt.Printf("Release Date:  %s\n", prov.Claims.ReleaseDate.Format(time.RFC3339))
		}
		if prov.Claims.BinaryDigest != "" {
			status := "Verified"
			if !prov.DigestMatched {
				status = "Not checked"
			}
			fmt.Printf("Binary Digest: %s (%s)\n", prov.Claims.BinaryDigest, status)
		}
	}
	if prov.VerifiedByKeyID != "" {
		fmt.Printf("Verified Key:  %s (Status: %s)\n", prov.VerifiedByKeyID, prov.VerifiedKeyStatus)
	}

	return nil
}
