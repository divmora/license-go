package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubKeyPath := fs.String("public-key", "", "Path to Ed25519 public key PEM file or base64 key string (optional; falls back to DIVMORA_PUBLIC_KEY/DIVMORA_PUBLIC_KEYS_PEM)")
	licenseSource := fs.String("license", "", "Path to license file or raw token string (optional; falls back to DIVMORA_LICENSE_KEY/DIVMORA_LICENSE_FILE)")
	product := fs.String("product", "", "Expected product name to assert")
	fingerprint := fs.String("fingerprint", "", "Expected node or cluster fingerprint to assert")
	env := fs.String("env", "", "Current deployment environment to assert against Scope.Environments")
	account := fs.String("account", "", "Current cloud account/tenant ID to assert against Scope.Accounts")
	region := fs.String("region", "", "Current cloud region to assert against Scope.Regions")
	cluster := fs.String("cluster", "", "Current cluster identifier to assert against Scope.Clusters")
	namespace := fs.String("namespace", "", "Current project/group namespace to assert against Scope.Namespaces")
	host := fs.String("host", "", "Current hostname or domain to assert against Scope.Hosts")
	customScopeFlag := fs.String("custom-scope", "", "Current custom scope assertions in key=val format separated by ';' or ',' (e.g. 'tier=platinum,datacenter=dc-1')")
	version := fs.String("version", "", "Current running software version to assert (e.g. '1.2.0')")
	buildDateFlag := fs.String("build-date", "", "Software binary build/release date to assert against maintenance window (RFC3339 or YYYY-MM-DD)")
	bslRelease := fs.String("bsl-release-date", "", "Software release date to configure BSL 1.1 Change Date (RFC3339 or YYYY-MM-DD)")
	bslYears := fs.Int("bsl-years", 3, "Duration in years before BSL 1.1 converts to Apache 2.0 (default: 3)")
	authTimeFlag := fs.String("authoritative-time", "", "Authoritative server timestamp (RFC3339 or HTTP Date header)")
	maxSkewFlag := fs.Duration("max-skew", 0, "Maximum allowed clock skew threshold (e.g. 5m, 1h) when using authoritative server time")
	strictClockFlag := fs.Bool("strict-clock", false, "Fail verification if clock tampering or excessive skew is detected")
	allowExpired := fs.Bool("allow-expired", false, "Allow signature verification even if license has expired")
	releaseAttestation := fs.String("release-attestation", "", "Path to release attestation file or raw DIVREL1 token")
	requireReleaseAttestation := fs.Bool("require-release-attestation", false, "Require a valid cryptographic release attestation")
	gitCommit := fs.String("git-commit", "", "Current git commit SHA to assert against release attestation")
	binaryPath := fs.String("binary", "", "Path to running binary executable to assert SHA-256 digest against release attestation")
	autoFingerprint := fs.Bool("auto-fingerprint", true, "Automatically resolve and match machine/cluster fingerprint for node-locked licenses (default: true)")
	crlFlag := fs.String("crl", "", "Path to signed Certificate Revocation List (CRL) file or raw DIVCRL1 token")
	strictCRL := fs.Bool("strict-crl", false, "Fail verification if CRL is expired past NextUpdate")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var ring *license.KeyRing
	var keySource string
	if *pubKeyPath != "" {
		r, err := license.ParseKeyRingFromString(*pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load public key from %s: %w", *pubKeyPath, err)
		}
		ring = r
		keySource = *pubKeyPath
	} else {
		resolvedKey, err := license.ResolveKeyRingWithSource()
		if err != nil {
			return fmt.Errorf("public verification key required: %w (pass -public-key or set %s / %s)", err, license.EnvPublicKey, license.EnvPublicKeysPEM)
		}
		ring = resolvedKey.KeyRing
		keySource = resolvedKey.Source
		if resolvedKey.FilePath != "" {
			keySource = fmt.Sprintf("%s (%s)", resolvedKey.Source, resolvedKey.FilePath)
		}
	}

	resolved, err := license.ResolveLicense(*licenseSource)
	if err != nil && *bslRelease == "" {
		return fmt.Errorf("failed to locate license: %w (pass -license or set %s / %s)", err, license.EnvLicenseKey, license.EnvLicenseFile)
	}

	var opts []license.ValidatorOption
	if *product != "" {
		opts = append(opts, license.WithProduct(*product))
	}
	if *fingerprint != "" {
		opts = append(opts, license.WithExpectedFingerprint(*fingerprint))
	} else if *autoFingerprint {
		opts = append(opts, license.WithAutoFingerprint(true))
	}
	if *env != "" {
		opts = append(opts, license.WithCurrentEnvironment(*env))
	}
	if *account != "" {
		opts = append(opts, license.WithCurrentAccount(*account))
	}
	if *region != "" {
		opts = append(opts, license.WithCurrentRegion(*region))
	}
	if *cluster != "" {
		opts = append(opts, license.WithCurrentCluster(*cluster))
	}
	if *namespace != "" {
		opts = append(opts, license.WithCurrentNamespace(*namespace))
	}
	if *host != "" {
		opts = append(opts, license.WithCurrentHost(*host))
	}
	if *customScopeFlag != "" {
		dims := strings.FieldsFunc(*customScopeFlag, func(r rune) bool {
			return r == ';' || r == ','
		})
		for _, item := range dims {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				dim := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if dim != "" && val != "" {
					opts = append(opts, license.WithCurrentCustomScope(dim, val))
				}
			}
		}
	}
	if *version != "" {
		opts = append(opts, license.WithCurrentVersion(*version))
	}
	if *buildDateFlag != "" {
		bDate, err := time.Parse(time.RFC3339, *buildDateFlag)
		if err != nil {
			bDate, err = time.Parse("2006-01-02", *buildDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -build-date %q: expected RFC3339 (2006-01-02T15:04:05Z07:00) or YYYY-MM-DD", *buildDateFlag)
			}
		}
		opts = append(opts, license.WithBuildDate(bDate))
	}
	if *bslRelease != "" {
		rDate, err := time.Parse(time.RFC3339, *bslRelease)
		if err != nil {
			rDate, err = time.Parse("2006-01-02", *bslRelease)
			if err != nil {
				return fmt.Errorf("invalid -bsl-release-date %q: expected RFC3339 or YYYY-MM-DD", *bslRelease)
			}
		}
		opts = append(opts, license.WithBSLPolicy(license.BSLPolicy{
			ReleaseDate:       rDate,
			ChangePeriodYears: *bslYears,
		}))
	}
	if *authTimeFlag != "" {
		aDate, err := license.ParseServerTimeHeader(*authTimeFlag)
		if err != nil {
			return fmt.Errorf("invalid -authoritative-time %q: %w", *authTimeFlag, err)
		}
		opts = append(opts, license.WithServerTimeAttestation(aDate, *maxSkewFlag))
		if *strictClockFlag {
			opts = append(opts, license.WithStrictClockDefense(true))
		}
	}
	if *allowExpired {
		opts = append(opts, license.WithAllowExpired(true))
	}
	if *releaseAttestation != "" {
		data, err := os.ReadFile(*releaseAttestation)
		if err == nil {
			opts = append(opts, license.WithReleaseAttestation(string(data)))
		} else {
			opts = append(opts, license.WithReleaseAttestation(*releaseAttestation))
		}
	}
	if *requireReleaseAttestation {
		opts = append(opts, license.WithRequireReleaseAttestation(true))
	}
	if *gitCommit != "" {
		opts = append(opts, license.WithCurrentGitCommit(*gitCommit))
	}
	if *binaryPath != "" {
		opts = append(opts, license.WithBinaryPath(*binaryPath))
	}
	if *crlFlag != "" {
		data, err := os.ReadFile(*crlFlag)
		if err == nil {
			opts = append(opts, license.WithRevocationList(string(data)))
		} else {
			opts = append(opts, license.WithRevocationList(*crlFlag))
		}
	} else if res, err := license.ResolveCRL(); err == nil {
		opts = append(opts, license.WithRevocationList(res.Content))
	}
	if *strictCRL {
		opts = append(opts, license.WithCRLStrictExpiry(true))
	}

	validator, err := license.NewValidatorWithKeyRing(ring, opts...)
	if err != nil {
		return fmt.Errorf("failed to initialize validator: %w", err)
	}

	var content string
	if resolved != nil {
		content = resolved.Content
	}
	result, err := validator.VerifyWithResult(content)
	if err != nil {
		return fmt.Errorf("VERIFICATION FAILED: %w", err)
	}

	fmt.Println("✓ VERIFICATION SUCCESSFUL: Signature is valid and claims match!")
	fmt.Printf("Status: %s\n", result.StatusMessage())
	if result.BSLConverted {
		fmt.Printf("ℹ️  GOVERNING LICENSE: %s (BSL 1.1 Change Date reached on %s; open source terms apply)\n",
			result.EffectiveLicense, result.ChangeDate.Format("2006-01-02"))
	}
	if result.ClockTampered {
		fmt.Printf("⚠️  WARNING: Clock tampering/skew detected (skew: %s); anchored evaluation to authoritative server time (%s).\n",
			result.ClockSkew, result.ServerTime.Format(time.RFC3339))
	} else if result.ServerTimeAttested {
		fmt.Printf("⏱️  Authoritative server time attested: %s (local skew: %s)\n",
			result.ServerTime.Format(time.RFC3339), result.ClockSkew)
	}
	if result.Provenance != nil && result.Provenance.Attested {
		provClaims := result.Provenance.Claims
		if provClaims != nil {
			fmt.Printf("📦 Attested Release: %s %s (signed by: %s)\n", provClaims.Product, provClaims.Version, result.Provenance.VerifiedByKeyID)
			if result.Provenance.DigestMatched {
				fmt.Printf("🔒 Binary Checksum: %s (VERIFIED)\n", provClaims.BinaryDigest)
			}
		}
	}
	if result.VerifiedByKeyID != "" {
		fmt.Printf("🔑 Verified by Key: %s (Status: %s)\n", result.VerifiedByKeyID, result.VerifiedByKeyStatus)
	}
	if result.FingerprintMatched {
		if result.ResolvedFingerprint != nil {
			fmt.Printf("🖥️  Node Lock: %s (%s, VERIFIED MATCH)\n", result.ResolvedFingerprint.Primary, result.ResolvedFingerprint.Platform)
		} else if result.Claims != nil && result.Claims.Fingerprint != "" {
			fmt.Printf("🖥️  Node Lock: %s (VERIFIED MATCH)\n", result.Claims.Fingerprint)
		}
	}
	if *pubKeyPath == "" && keySource != "" {
		fmt.Printf("🗝️  Loaded public key from: %s\n", keySource)
	}
	if resolved != nil && resolved.Source != "explicit_file" && resolved.Source != "explicit_token" {
		fmt.Printf("ℹ️  Loaded license from: %s\n", resolved.Source)
	}
	if result.InGracePeriod {
		fmt.Printf("⚠️  WARNING: License is currently operating in GRACE PERIOD (%d grace days remaining, cutoff: %s)\n",
			result.GraceDaysRemaining, result.EffectiveExpiry.Format(time.RFC3339))
	}
	fmt.Println("--------------------------------------------------")
	claimsJSON, _ := json.MarshalIndent(result.Claims, "", "  ")
	fmt.Println(string(claimsJSON))
	return nil
}
