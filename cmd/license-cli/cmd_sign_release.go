package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func runSignRelease(args []string) error {
	fs := flag.NewFlagSet("sign-release", flag.ExitOnError)
	privKeyPath := fs.String("private-key", "", "Path to Ed25519 private key PEM file (required)")
	product := fs.String("product", "", "Software product name (required)")
	version := fs.String("version", "", "Official release version string (e.g. 'v1.2.0') (required)")
	gitCommit := fs.String("git-commit", "", "Official Git commit SHA")
	buildDateFlag := fs.String("build-date", "", "Build timestamp (RFC3339 or YYYY-MM-DD, defaults to now)")
	releaseDateFlag := fs.String("release-date", "", "BSL 1.1 release date (RFC3339 or YYYY-MM-DD, defaults to build-date)")
	binaryPath := fs.String("binary", "", "Path to compiled binary executable to automatically compute SHA-256 digest")
	digestFlag := fs.String("digest", "", "Explicit binary digest (sha256:<hex>)")
	authority := fs.String("authority", "divmora.com/release", "Issuing release authority")
	keyID := fs.String("key-id", "", "Signing Key ID hint")
	metaFlag := fs.String("meta", "", "Custom release metadata key-value pairs (k=v,k2=v2)")
	armored := fs.Bool("armored", true, "Output armored PEM block")
	outFile := fs.String("out", "", "Output file path (prints to stdout if omitted)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *privKeyPath == "" {
		return errors.New("private key required: pass -private-key <path>")
	}
	if *product == "" {
		return errors.New("product name required: pass -product <name>")
	}
	if *version == "" {
		return errors.New("version required: pass -version <version>")
	}

	privKeyPEM, err := os.ReadFile(*privKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	privKey, err := license.ParsePrivateKeyFromPEM(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	now := time.Now().UTC()
	buildDate := now
	if *buildDateFlag != "" {
		bDate, err := time.Parse(time.RFC3339, *buildDateFlag)
		if err != nil {
			bDate, err = time.Parse("2006-01-02", *buildDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -build-date %q: expected RFC3339 or YYYY-MM-DD", *buildDateFlag)
			}
		}
		buildDate = bDate.UTC()
	}

	releaseDate := buildDate
	if *releaseDateFlag != "" {
		rDate, err := time.Parse(time.RFC3339, *releaseDateFlag)
		if err != nil {
			rDate, err = time.Parse("2006-01-02", *releaseDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -release-date %q: expected RFC3339 or YYYY-MM-DD", *releaseDateFlag)
			}
		}
		releaseDate = rDate.UTC()
	}

	binaryDigest := strings.TrimSpace(*digestFlag)
	if binaryDigest == "" && *binaryPath != "" {
		d, err := license.ComputeFileDigest(*binaryPath)
		if err != nil {
			return fmt.Errorf("failed to compute digest of binary %s: %w", *binaryPath, err)
		}
		binaryDigest = d
	}

	meta := parseMetadata(*metaFlag)

	claims := license.ReleaseClaims{
		Product:      *product,
		Version:      *version,
		GitCommit:    *gitCommit,
		BuildDate:    buildDate,
		ReleaseDate:  releaseDate,
		BinaryDigest: binaryDigest,
		Authority:    *authority,
		KeyID:        *keyID,
		IssuedAt:     now,
		Metadata:     meta,
	}

	var output string
	var opts []license.SignerOption
	if *keyID != "" {
		opts = append(opts, license.WithSignerKeyID(*keyID))
	}

	if *armored {
		output, err = license.SignReleaseArmored(claims, privKey, opts...)
	} else {
		output, err = license.SignRelease(claims, privKey, opts...)
	}
	if err != nil {
		return fmt.Errorf("failed to sign release attestation: %w", err)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("✓ Successfully issued release attestation for %s (%s) -> %s\n", *product, *version, *outFile)
	} else {
		fmt.Print(output)
	}

	return nil
}
