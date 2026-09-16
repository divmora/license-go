package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
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

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "Directory to write key files")
	privName := fs.String("priv-name", "private.pem", "Filename for private key")
	pubName := fs.String("pub-name", "public.pem", "Filename for public key")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", *outDir, err)
	}

	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		return err
	}

	privPath := filepath.Join(*outDir, *privName)
	pubPath := filepath.Join(*outDir, *pubName)

	if err := license.SavePrivateKeyToPEMFile(priv, privPath, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := license.SavePublicKeyToPEMFile(pub, pubPath, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	fmt.Println("✓ Generated Ed25519 Key Pair successfully:")
	fmt.Printf("  Private Key: %s (mode 0600)\n", privPath)
	fmt.Printf("  Public Key:  %s (mode 0644)\n", pubPath)
	return nil
}

func runIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	privKeyPath := fs.String("private-key", "", "Path to Ed25519 private key PEM file (required)")
	product := fs.String("product", "", "Product name e.g. gitlab-fleet-governor, otel-aws-log-processor (required)")
	customer := fs.String("customer", "", "Licensee / Customer name (required)")
	email := fs.String("email", "", "Contact email address (optional)")
	orgID := fs.String("org-id", "", "Customer / Organization tenant ID (optional)")
	plan := fs.String("plan", "enterprise", "License tier: community, starter, pro, enterprise, trial")
	validDays := fs.Int("valid-days", 365, "Validity duration in days (0 for perpetual)")
	graceDays := fs.Int("grace-days", 0, "Grace period duration in days after expiration (default: 0)")
	featuresFlag := fs.String("features", "", "Comma-separated list of features (e.g. 'ha,audit-logs,sso')")
	limitsFlag := fs.String("limits", "", "Comma-separated limits in key=val format (e.g. 'max_runners=50,max_nodes=10')")
	metaFlag := fs.String("meta", "", "Comma-separated metadata in key=val format (e.g. 'env=prod,region=us-east')")
	fingerprint := fs.String("fingerprint", "", "Optional cluster/node fingerprint binding")
	scopeEnvs := fs.String("scope-envs", "", "Comma-separated authorized environments (e.g. 'production,staging')")
	scopeAccounts := fs.String("scope-accounts", "", "Comma-separated authorized account IDs (e.g. '123456789012')")
	scopeRegions := fs.String("scope-regions", "", "Comma-separated authorized regions (e.g. 'us-east-1,us-west-2')")
	scopeClusters := fs.String("scope-clusters", "", "Comma-separated authorized clusters (e.g. 'prod-eks-01')")
	scopeNamespaces := fs.String("scope-namespaces", "", "Comma-separated authorized namespaces/groups (e.g. 'gitlab.com/acme/*')")
	scopeHosts := fs.String("scope-hosts", "", "Comma-separated authorized hostnames/domains (e.g. '*.acme.corp,runner-*.internal')")
	scopeCustomFlag := fs.String("scope-custom", "", "Custom scope dimensions in key=val format; multiple dimensions separated by ';' and values separated by ',' (e.g. 'tier=platinum,gold;datacenter=dc-1')")
	armored := fs.Bool("armored", true, "Output license in armored text format (default: true)")
	outFile := fs.String("out", "", "Output file path (default: stdout)")
	kid := fs.String("kid", "", "Optional Key ID or descriptor to embed in token claims (e.g. 'divmora-2026-root')")
	maxVersion := fs.String("max-version", "", "Maximum authorized software version for perpetual license (e.g. '1.*', '2.4.0')")
	allowedVersionsFlag := fs.String("allowed-versions", "", "Comma-separated authorized versions or patterns (e.g. '1.*,2.0.*')")
	maintenanceDays := fs.Int("maintenance-days", 0, "Maintenance/update entitlement duration in days from issue date")
	reqPath := fs.String("request", "", "Path to air-gapped license request file (.divreq or PEM) to fulfill")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var licReq *license.LicenseRequest
	if *reqPath != "" {
		parsed, err := license.ParseLicenseRequestFile(*reqPath)
		if err != nil {
			return fmt.Errorf("failed to load license request from %s: %w", *reqPath, err)
		}
		licReq = parsed
		if *customer == "" {
			*customer = licReq.Customer
		}
		if *product == "" {
			*product = licReq.Product
		}
		if *plan == "enterprise" && licReq.Plan != "" {
			*plan = licReq.Plan
		}
		if *fingerprint == "" && licReq.Fingerprint.Primary != "" {
			*fingerprint = licReq.Fingerprint.Primary
		}
	}

	if *privKeyPath == "" {
		return fmt.Errorf("-private-key is required")
	}
	if *product == "" {
		return fmt.Errorf("-product is required (or provide -request)")
	}
	if *customer == "" {
		return fmt.Errorf("-customer is required (or provide -request)")
	}

	var signerOpts []license.SignerOption
	if *kid != "" {
		signerOpts = append(signerOpts, license.WithSignerKeyID(*kid))
	}

	signer, err := license.NewSignerFromPEMFile(*privKeyPath, signerOpts...)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	now := time.Now().UTC()
	var expiresAt time.Time
	if *validDays > 0 {
		expiresAt = now.Add(time.Duration(*validDays) * 24 * time.Hour)
	}

	var features []string
	if *featuresFlag != "" {
		for _, f := range strings.Split(*featuresFlag, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				features = append(features, f)
			}
		}
	} else if licReq != nil && len(licReq.RequestedFeatures) > 0 {
		features = licReq.RequestedFeatures
	}

	limits := make(map[string]int64)
	if *limitsFlag != "" {
		for _, item := range strings.Split(*limitsFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				val, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid limit value in %q: %w", item, err)
				}
				limits[strings.TrimSpace(parts[0])] = val
			}
		}
	} else if licReq != nil && len(licReq.RequestedLimits) > 0 {
		for k, v := range licReq.RequestedLimits {
			limits[k] = v
		}
	}

	meta := make(map[string]string)
	if *metaFlag != "" {
		for _, item := range strings.Split(*metaFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				meta[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	parseSlice := func(val string) []string {
		if val == "" {
			return nil
		}
		var list []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				list = append(list, s)
			}
		}
		return list
	}

	envs := parseSlice(*scopeEnvs)
	accounts := parseSlice(*scopeAccounts)
	regions := parseSlice(*scopeRegions)
	clusters := parseSlice(*scopeClusters)
	namespaces := parseSlice(*scopeNamespaces)
	hosts := parseSlice(*scopeHosts)
	customScope := parseCustomScope(*scopeCustomFlag)

	var scope *license.Scope
	if len(envs) > 0 || len(accounts) > 0 || len(regions) > 0 || len(clusters) > 0 || len(namespaces) > 0 || len(hosts) > 0 || len(customScope) > 0 {
		scope = &license.Scope{
			Environments: envs,
			Accounts:     accounts,
			Regions:      regions,
			Clusters:     clusters,
			Namespaces:   namespaces,
			Hosts:        hosts,
			Custom:       customScope,
		}
	}

	var maintenanceExpiresAt time.Time
	if *maintenanceDays > 0 {
		maintenanceExpiresAt = now.Add(time.Duration(*maintenanceDays) * 24 * time.Hour)
	}

	claims := license.Claims{
		Customer: license.Customer{
			Name:  *customer,
			Email: *email,
			OrgID: *orgID,
		},
		Product:              *product,
		Plan:                 *plan,
		IssuedAt:             now,
		ExpiresAt:            expiresAt,
		GracePeriodDays:      *graceDays,
		Features:             features,
		Limits:               limits,
		Scope:                scope,
		Fingerprint:          *fingerprint,
		MaxVersion:           *maxVersion,
		AllowedVersions:      parseSlice(*allowedVersionsFlag),
		MaintenanceExpiresAt: maintenanceExpiresAt,
		Metadata:             meta,
	}

	var output string
	if *armored {
		output, err = signer.SignArmored(claims)
	} else {
		output, err = signer.Sign(claims)
	}
	if err != nil {
		return fmt.Errorf("failed to sign license: %w", err)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("✓ Successfully issued license for %s (%s) -> %s\n", claims.Customer.Name, *product, *outFile)
	} else {
		fmt.Print(output)
	}

	return nil
}

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

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	licenseSource := fs.String("license", "", "Path to license file or raw token string (optional; falls back to DIVMORA_LICENSE_KEY/DIVMORA_LICENSE_FILE)")
	jsonOutput := fs.Bool("json", false, "Output claims in raw JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	resolved, err := license.ResolveLicense(*licenseSource)
	if err != nil {
		return fmt.Errorf("failed to locate license: %w (pass -license or set %s / %s)", err, license.EnvLicenseKey, license.EnvLicenseFile)
	}

	claims, err := license.Inspect(resolved.Content)
	if err != nil {
		return fmt.Errorf("failed to inspect license: %w", err)
	}

	if *jsonOutput {
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Println(string(claimsJSON))
		return nil
	}

	fmt.Println("License Inspection (Unverified Signature):")
	if resolved.Source != "explicit_file" && resolved.Source != "explicit_token" {
		fmt.Printf("ℹ️  Loaded license from: %s\n", resolved.Source)
	}
	fmt.Print(claims.FormatInspect())
	return nil
}

func runKeyring(args []string) error {
	var bundleName string
	var ring *license.KeyRing
	var err error

	if len(args) >= 1 {
		bundleName = args[0]
		ring, err = license.ParseKeyRingFromString(bundleName)
		if err != nil {
			return fmt.Errorf("failed to load keyring bundle: %w", err)
		}
	} else {
		resolved, rErr := license.ResolveKeyRingWithSource()
		if rErr != nil {
			return fmt.Errorf("usage: license-cli keyring <public-keys-bundle.pem> (or set %s / %s)", license.EnvPublicKey, license.EnvPublicKeysPEM)
		}
		ring = resolved.KeyRing
		bundleName = resolved.Source
		if resolved.FilePath != "" {
			bundleName = fmt.Sprintf("%s (%s)", resolved.Source, resolved.FilePath)
		}
	}

	keys := ring.Keys()
	fmt.Printf("KeyRing Bundle: %s (%d public key(s))\n", bundleName, len(keys))
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("%-6s %-12s %-24s %-20s\n", "INDEX", "STATUS", "ID / FINGERPRINT", "ROLE")
	fmt.Println("--------------------------------------------------------------------------------")
	primary := ring.Primary()
	for i, k := range keys {
		role := "Fallback"
		if primary != nil && k == primary {
			role = "Primary (Active)"
		}
		fmt.Printf("%-6d %-12s %-24s %-20s\n", i+1, k.Status, k.ID, role)
	}
	fmt.Println("--------------------------------------------------------------------------------")
	return nil
}

func parseCustomScope(raw string) map[string][]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	result := make(map[string][]string)

	var entries []string
	if strings.Contains(raw, ";") {
		entries = strings.Split(raw, ";")
	} else if strings.Count(raw, "=") > 1 && strings.Contains(raw, ",") {
		entries = strings.Split(raw, ",")
	} else {
		entries = []string{raw}
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		dim := strings.TrimSpace(parts[0])
		valsPart := strings.TrimSpace(parts[1])
		if dim == "" {
			continue
		}

		valFields := strings.FieldsFunc(valsPart, func(r rune) bool {
			return r == ',' || r == '|'
		})
		for _, v := range valFields {
			v = strings.TrimSpace(v)
			if v != "" {
				result[dim] = append(result[dim], v)
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseMetadata(raw string) map[string]string {
	meta := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return meta
	}
	for _, item := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				meta[k] = v
			}
		}
	}
	return meta
}

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

func runInspectRelease(args []string) error {
	fs := flag.NewFlagSet("inspect-release", flag.ExitOnError)
	attestationSource := fs.String("attestation", "", "Path to release attestation file or raw DIVREL1 token")
	jsonOutput := fs.Bool("json", false, "Output claims in raw JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var rawToken string
	if *attestationSource != "" {
		rawToken = *attestationSource
		if data, err := os.ReadFile(*attestationSource); err == nil {
			rawToken = string(data)
		}
	} else if len(fs.Args()) > 0 {
		rawToken = fs.Args()[0]
		if data, err := os.ReadFile(rawToken); err == nil {
			rawToken = string(data)
		}
	} else {
		return errors.New("attestation required: pass -attestation <file or token> or provide token argument")
	}

	claims, err := license.InspectRelease(rawToken)
	if err != nil {
		return fmt.Errorf("failed to inspect release attestation: %w", err)
	}

	if *jsonOutput {
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Println(string(claimsJSON))
		return nil
	}

	fmt.Print(claims.FormatInspect())
	return nil
}

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

func runBSLEval(args []string) error {
	fs := flag.NewFlagSet("bsl-eval", flag.ExitOnError)
	releaseDateFlag := fs.String("release-date", "", "Software compilation/release date (YYYY-MM-DD or RFC3339)")
	changeDateFlag := fs.String("change-date", "", "Explicit open-source Change Date override (YYYY-MM-DD or RFC3339)")
	yearsFlag := fs.Int("years", 3, "BSL change period in years (default: 3)")
	changeLicFlag := fs.String("change-license", "Apache-2.0", "Target open-source license upon conversion (default: Apache-2.0)")
	productFlag := fs.String("product", "divmora-product", "Product name")
	envFlag := fs.String("env", "", "Current deployment environment (e.g. production, staging, development)")
	usageFlag := fs.String("usage", "", "Active runtime consumption counts (e.g. 'max_nodes=6,max_runners=15')")
	featuresFlag := fs.String("features", "", "Comma-separated feature flags requested (e.g. 'basic-ingest,metrics')")
	freeLimitsFlag := fs.String("free-limits", "", "Free community quota limits in key=val format (e.g. 'max_nodes=10,max_runners=25')")
	exemptEnvsFlag := fs.String("exempt-envs", "", "Comma-separated non-production exempt environments (default: standard non-prod envs; 'none' to disable)")
	excludedFeatsFlag := fs.String("excluded-features", "", "Features strictly excluded from free tier / requiring commercial license (e.g. 'sso,audit-logs')")
	timeFlag := fs.String("time", "", "Reference evaluation timestamp (default: current time)")
	jsonOutput := fs.Bool("json", false, "Output evaluation result in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var releaseDate time.Time
	if *releaseDateFlag != "" {
		t, err := time.Parse(time.RFC3339, *releaseDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *releaseDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -release-date %q: expected RFC3339 or YYYY-MM-DD", *releaseDateFlag)
			}
		}
		releaseDate = t
	}

	var explicitChangeDate time.Time
	if *changeDateFlag != "" {
		t, err := time.Parse(time.RFC3339, *changeDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *changeDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -change-date %q: expected RFC3339 or YYYY-MM-DD", *changeDateFlag)
			}
		}
		explicitChangeDate = t
	}

	if releaseDate.IsZero() && explicitChangeDate.IsZero() {
		return errors.New("-release-date or -change-date is required for BSL entitlement evaluation")
	}

	policy := license.BSLPolicy{
		ReleaseDate:        releaseDate,
		ExplicitChangeDate: explicitChangeDate,
		ChangePeriodYears:  *yearsFlag,
		ChangeLicense:      *changeLicFlag,
		Product:            *productFlag,
	}

	parseList := func(val string) []string {
		if strings.TrimSpace(val) == "" {
			return nil
		}
		var list []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				list = append(list, s)
			}
		}
		return list
	}

	// 1. Non-production exemption grant
	if strings.ToLower(strings.TrimSpace(*exemptEnvsFlag)) != "none" {
		var exemptEnvs []string
		if *exemptEnvsFlag != "" {
			exemptEnvs = parseList(*exemptEnvsFlag)
		}
		policy.AddGrant(license.NewNonProductionGrant("Non-Production Exemption", exemptEnvs...))
	}

	// 2. Free community tier grant
	if strings.TrimSpace(*freeLimitsFlag) != "" {
		limits := make(map[string]int64)
		for _, item := range strings.Split(*freeLimitsFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid free limit in %q: %w", item, err)
				}
				limits[k] = v
			}
		}
		var excludedFeats []string
		if *excludedFeatsFlag != "" {
			excludedFeats = parseList(*excludedFeatsFlag)
		}
		policy.AddGrant(license.NewFreeTierGrant("Community Free Tier", limits, excludedFeats...))
	}

	// 3. Resolve evaluation reference timestamp
	evalTime := time.Now()
	if *timeFlag != "" {
		t, err := time.Parse(time.RFC3339, *timeFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *timeFlag)
			if err != nil {
				return fmt.Errorf("invalid -time %q: expected RFC3339 or YYYY-MM-DD", *timeFlag)
			}
		}
		evalTime = t
	}

	// 4. Resolve environment
	env := strings.TrimSpace(*envFlag)
	if env == "" {
		for _, envVar := range []string{"ENV", "ENVIRONMENT", "APP_ENV", "NODE_ENV"} {
			if v := os.Getenv(envVar); v != "" {
				env = v
				break
			}
		}
	}

	// 5. Parse runtime usage metrics
	usage := make(map[string]int64)
	if strings.TrimSpace(*usageFlag) != "" {
		for _, item := range strings.Split(*usageFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid usage value in %q: %w", item, err)
				}
				usage[k] = v
			}
		}
	}

	// 6. Parse features
	features := parseList(*featuresFlag)

	// 7. Evaluate entitlement
	req := license.BSLUsageRequest{
		Environment: env,
		Usage:       usage,
		Features:    features,
		Time:        evalTime,
	}

	result := policy.EvaluateEntitlement(req)

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
		if !result.Authorized {
			return fmt.Errorf("commercial license required under BSL 1.1 terms: %s", result.Reason)
		}
		return nil
	}

	// Terminal Formatted Output
	fmt.Println(strings.Repeat("=", 72))
	fmt.Println("                 DIVMORA BSL 1.1 ENTITLEMENT EVALUATION")
	fmt.Println(strings.Repeat("=", 72))

	var decisionLabel string
	if result.GrantType == license.BSLGrantTypeConverted {
		decisionLabel = fmt.Sprintf("OPEN SOURCE [✓ Converted to %s]", result.EffectiveLicense)
	} else if result.Authorized {
		decisionLabel = fmt.Sprintf("AUTHORIZED [✓ Additional Use Grant: %s]", result.MatchingGrant)
	} else {
		decisionLabel = "COMMERCIAL LICENSE REQUIRED [❌ Exceeds Free Tier Bounds]"
	}
	fmt.Printf("%-24s %s\n", "Decision:", decisionLabel)
	fmt.Printf("%-24s %s\n", "Effective License:", result.EffectiveLicense)
	if env != "" {
		fmt.Printf("%-24s %s\n", "Environment:", env)
	}
	if !result.ChangeDate.IsZero() {
		targetLic := policy.ChangeLicense
		if targetLic == "" {
			targetLic = license.DefaultBSLChangeLicense
		}
		if result.DaysUntilConversion > 0 {
			fmt.Printf("%-24s %s (converts to %s in %d days)\n",
				"BSL Change Date:", result.ChangeDate.Format("2006-01-02"), targetLic, result.DaysUntilConversion)
		} else {
			fmt.Printf("%-24s %s (converted to %s)\n",
				"BSL Change Date:", result.ChangeDate.Format("2006-01-02"), targetLic)
		}
	}
	fmt.Printf("%-24s %s\n", "Status Summary:", result.Reason)

	if len(result.Evaluations) > 0 {
		fmt.Println("\nEVALUATED ADDITIONAL USE GRANTS:")
		fmt.Printf("  %-28s %-12s %s\n", "Grant Name", "Status", "Details")
		fmt.Println("  " + strings.Repeat("─", 68))
		for _, ev := range result.Evaluations {
			statusStr := "Matched"
			if !ev.Matched {
				statusStr = "Excluded"
			}
			fmt.Printf("  %-28s %-12s %s\n", ev.GrantName, statusStr, ev.Reason)
		}
	}
	fmt.Println(strings.Repeat("=", 72))

	if !result.Authorized {
		return fmt.Errorf("commercial license required under BSL 1.1 terms: %s", result.Reason)
	}
	return nil
}

func runFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	platform := fs.String("platform", "auto", "Target platform resolver: auto, host, aws, lambda, k8s")
	asJSON := fs.Bool("json", false, "Output machine fingerprint in JSON format")
	quiet := fs.Bool("quiet", false, "Output only the primary fingerprint string (for scripts)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var resolver license.FingerprintResolver
	switch strings.ToLower(*platform) {
	case "auto":
		resolver = license.NewDefaultCompositeResolver()
	case "host":
		resolver = license.NewHostResolver()
	case "aws", "aws-ec2", "ec2":
		resolver = license.NewAWSEC2Resolver()
	case "lambda", "aws-lambda":
		resolver = license.NewAWSLambdaResolver()
	case "k8s", "kubernetes":
		resolver = license.NewKubernetesResolver()
	default:
		return fmt.Errorf("unknown platform %q; valid values are: auto, host, aws, lambda, k8s", *platform)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fp, err := resolver.Resolve(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve machine fingerprint: %w", err)
	}

	if *quiet {
		fmt.Println(fp.Primary)
		return nil
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(fp)
	}

	fmt.Println(strings.Repeat("=", 72))
	fmt.Println("                       MACHINE FINGERPRINT")
	fmt.Println(strings.Repeat("=", 72))
	fmt.Printf("  %-20s %s\n", "Primary ID:", fp.Primary)
	fmt.Printf("  %-20s %s\n", "Platform:", fp.Platform)
	fmt.Printf("  %-20s %s\n", "Short Digest:", fp.ShortDigest)
	fmt.Printf("  %-20s %s\n", "Canonical Digest:", fp.CanonicalDigest)
	fmt.Printf("  %-20s %s\n", "Resolved At:", fp.ResolvedAt.Format(time.RFC3339))

	if len(fp.Components) > 0 {
		fmt.Println("\nHARDWARE & SYSTEM COMPONENTS:")
		var keys []string
		for k := range fp.Components {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  • %-20s %s\n", k+":", fp.Components[k])
		}
	}
	fmt.Println(strings.Repeat("=", 72))
	return nil
}

func runRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	customer := fs.String("customer", "", "Licensee / Customer name (required)")
	product := fs.String("product", "", "Product name e.g. gitlab-fleet-governor (required)")
	plan := fs.String("plan", "enterprise", "Requested license tier: starter, pro, enterprise")
	platform := fs.String("platform", "auto", "Hardware resolver platform: auto, host, aws, lambda, k8s")
	limitsFlag := fs.String("limits", "", "Comma-separated requested limits in key=val format (e.g. 'runners=50,users=100')")
	featuresFlag := fs.String("features", "", "Comma-separated requested features (e.g. 'sso,audit-logs')")
	notes := fs.String("notes", "", "Optional deployment notes or request context")
	outFile := fs.String("out", "", "Output file path (default: stdout, e.g. 'request.divreq')")
	asJSON := fs.Bool("json", false, "Output raw JSON instead of armored PEM block")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *customer == "" {
		return fmt.Errorf("-customer is required")
	}
	if *product == "" {
		return fmt.Errorf("-product is required")
	}

	var resolver license.FingerprintResolver
	switch strings.ToLower(*platform) {
	case "auto":
		resolver = license.NewDefaultCompositeResolver()
	case "host":
		resolver = license.NewHostResolver()
	case "aws", "aws-ec2", "ec2":
		resolver = license.NewAWSEC2Resolver()
	case "lambda", "aws-lambda":
		resolver = license.NewAWSLambdaResolver()
	case "k8s", "kubernetes":
		resolver = license.NewKubernetesResolver()
	default:
		return fmt.Errorf("unknown platform %q; valid values are: auto, host, aws, lambda, k8s", *platform)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fp, err := resolver.Resolve(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve machine fingerprint: %w", err)
	}

	req := license.NewLicenseRequest(*customer, *product, *fp)
	req.Plan = *plan
	req.Notes = *notes

	if *featuresFlag != "" {
		for _, f := range strings.Split(*featuresFlag, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				req.RequestedFeatures = append(req.RequestedFeatures, f)
			}
		}
	}

	if *limitsFlag != "" {
		req.RequestedLimits = make(map[string]int64)
		for _, item := range strings.Split(*limitsFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				val, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid limit value in %q: %w", item, err)
				}
				req.RequestedLimits[strings.TrimSpace(parts[0])] = val
			}
		}
	}

	var outBytes []byte
	if *asJSON {
		outBytes, err = json.MarshalIndent(req, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
		outBytes = append(outBytes, '\n')
	} else {
		outBytes, err = req.Armored()
		if err != nil {
			return fmt.Errorf("failed to format armored request: %w", err)
		}
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, outBytes, 0644); err != nil {
			return fmt.Errorf("failed to write request file %s: %w", *outFile, err)
		}
		fmt.Printf("✓ Successfully generated air-gapped license request -> %s\n", *outFile)
		fmt.Printf("  Primary Fingerprint: %s (%s)\n", fp.Primary, fp.Platform)
	} else {
		fmt.Print(string(outBytes))
	}

	return nil
}
