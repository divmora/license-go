package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	licenseSource := fs.String("license", "", "Path to license file or raw token string (optional; falls back to DIVMORA_LICENSE_KEY/DIVMORA_LICENSE_FILE)")
	pubKeyPath := fs.String("public-key", "", "Path to public key PEM or PEM bundle file (optional; falls back to DIVMORA_PUBLIC_KEY/DIVMORA_PUBLIC_KEYS_PEM)")
	product := fs.String("product", "", "Expected product name to assert")
	usageFlag := fs.String("usage", "", "Current live usage counts in key=val format separated by ',' (e.g. 'max_runners=142,max_nodes=6')")
	releaseAttestation := fs.String("release-attestation", "", "Path to release attestation file or raw DIVREL1 token")
	binaryPath := fs.String("binary", "", "Path to running binary executable to assert SHA-256 digest")
	bslRelease := fs.String("bsl-release-date", "", "Software release date to configure BSL 1.1 Change Date (RFC3339 or YYYY-MM-DD)")
	bslYears := fs.Int("bsl-years", 3, "Duration in years before BSL 1.1 converts to Apache 2.0 (default: 3)")
	title := fs.String("title", "", "Custom banner title")
	compact := fs.Bool("compact", false, "Enable compact single-card output")
	noQuotas := fs.Bool("no-quotas", false, "Omit resource quotas and capacity table")
	noFeatures := fs.Bool("no-features", false, "Omit entitled features list")
	noScopes := fs.Bool("no-scopes", false, "Omit operational scope constraints")
	noProvenance := fs.Bool("no-provenance", false, "Omit release provenance attestation details")
	crlFlag := fs.String("crl", "", "Path to signed Certificate Revocation List (CRL) file or raw DIVCRL1 token")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Parse live usage map
	usage := make(map[string]int64)
	if strings.TrimSpace(*usageFlag) != "" {
		for _, item := range strings.Split(*usageFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err == nil {
					usage[k] = v
				}
			}
		}
	}

	var formatOpts []license.StatusFormatterOption
	if len(usage) > 0 {
		formatOpts = append(formatOpts, license.WithStatusUsage(usage))
	}
	if *title != "" {
		formatOpts = append(formatOpts, license.WithStatusBannerTitle(*title))
	}
	if *compact {
		formatOpts = append(formatOpts, license.WithStatusCompact(true))
	}
	if *noQuotas {
		formatOpts = append(formatOpts, license.WithStatusIncludeQuotas(false))
	}
	if *noFeatures {
		formatOpts = append(formatOpts, license.WithStatusIncludeFeatures(false))
	}
	if *noScopes {
		formatOpts = append(formatOpts, license.WithStatusIncludeScopes(false))
	}
	if *noProvenance {
		formatOpts = append(formatOpts, license.WithStatusIncludeProvenance(false))
	}

	// 1. Try to resolve KeyRing
	var ring *license.KeyRing
	if *pubKeyPath != "" {
		r, err := license.ParseKeyRingFromString(*pubKeyPath)
		if err == nil {
			ring = r
		}
	} else {
		resolvedKey, err := license.ResolveKeyRingWithSource()
		if err == nil {
			ring = resolvedKey.KeyRing
		}
	}

	// 2. Try to resolve license
	resolvedLic, licErr := license.ResolveLicense(*licenseSource)

	// 3. If KeyRing is available, attempt full cryptographic verification
	if ring != nil && (resolvedLic != nil || *bslRelease != "" || *licenseSource != "") {
		var valOpts []license.ValidatorOption
		if *product != "" {
			valOpts = append(valOpts, license.WithProduct(*product))
		}
		if *bslRelease != "" {
			rDate, err := time.Parse(time.RFC3339, *bslRelease)
			if err != nil {
				rDate, err = time.Parse("2006-01-02", *bslRelease)
			}
			if err == nil {
				valOpts = append(valOpts, license.WithBSLPolicy(license.BSLPolicy{
					ReleaseDate:       rDate,
					ChangePeriodYears: *bslYears,
				}))
			}
		}
		if *releaseAttestation != "" {
			data, err := os.ReadFile(*releaseAttestation)
			if err == nil {
				valOpts = append(valOpts, license.WithReleaseAttestation(string(data)))
			} else {
				valOpts = append(valOpts, license.WithReleaseAttestation(*releaseAttestation))
			}
		}
		if *binaryPath != "" {
			valOpts = append(valOpts, license.WithBinaryPath(*binaryPath))
		}
		if *crlFlag != "" {
			if data, err := os.ReadFile(*crlFlag); err == nil {
				valOpts = append(valOpts, license.WithRevocationList(string(data)))
			} else {
				valOpts = append(valOpts, license.WithRevocationList(*crlFlag))
			}
		} else if res, err := license.ResolveCRL(); err == nil {
			valOpts = append(valOpts, license.WithRevocationList(res.Content))
		}

		validator, err := license.NewValidatorWithKeyRing(ring, valOpts...)
		if err == nil {
			var raw string
			if resolvedLic != nil {
				raw = resolvedLic.Content
			}
			result, vErr := validator.VerifyWithResult(raw)
			if vErr == nil {
				fmt.Print(result.FormatStatus(formatOpts...))
				return nil
			}
		}
	}

	// 4. Fallback to unverified Claims inspection
	if resolvedLic != nil {
		claims, err := license.Inspect(resolvedLic.Content)
		if err != nil {
			return fmt.Errorf("failed to inspect license: %w", err)
		}
		fmt.Print(claims.FormatStatus(formatOpts...))
		return nil
	}

	if licErr != nil {
		return fmt.Errorf("failed to locate license: %w (pass -license or set %s / %s)", licErr, license.EnvLicenseKey, license.EnvLicenseFile)
	}

	return errors.New("no license available to format status")
}
