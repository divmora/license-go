package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	case "keyring":
		err = runKeyring(args)
	case "help", "-h", "--help":
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
  keygen    Generate a new Ed25519 private/public keypair
  issue     Issue and sign a new software license
  verify    Verify a license signature and evaluate its claims
  inspect   Decode and inspect license claims without verification
  keyring   Inspect public keys inside a PEM bundle file
  help      Display help information

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
	armored := fs.Bool("armored", true, "Output license in armored text format (default: true)")
	outFile := fs.String("out", "", "Output file path (default: stdout)")
	kid := fs.String("kid", "", "Optional Key ID or descriptor to embed in token claims (e.g. 'divmora-2026-root')")
	maxVersion := fs.String("max-version", "", "Maximum authorized software version for perpetual license (e.g. '1.*', '2.4.0')")
	allowedVersionsFlag := fs.String("allowed-versions", "", "Comma-separated authorized versions or patterns (e.g. '1.*,2.0.*')")
	maintenanceDays := fs.Int("maintenance-days", 0, "Maintenance/update entitlement duration in days from issue date")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *privKeyPath == "" {
		return fmt.Errorf("-private-key is required")
	}
	if *product == "" {
		return fmt.Errorf("-product is required")
	}
	if *customer == "" {
		return fmt.Errorf("-customer is required")
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

	var scope *license.Scope
	if len(envs) > 0 || len(accounts) > 0 || len(regions) > 0 || len(clusters) > 0 || len(namespaces) > 0 || len(hosts) > 0 {
		scope = &license.Scope{
			Environments: envs,
			Accounts:     accounts,
			Regions:      regions,
			Clusters:     clusters,
			Namespaces:   namespaces,
			Hosts:        hosts,
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
	pubKeyPath := fs.String("public-key", "", "Path to Ed25519 public key PEM file (required)")
	licenseSource := fs.String("license", "", "Path to license file or raw token string (optional; falls back to DIVMORA_LICENSE_KEY/DIVMORA_LICENSE_FILE)")
	product := fs.String("product", "", "Expected product name to assert")
	fingerprint := fs.String("fingerprint", "", "Expected node or cluster fingerprint to assert")
	env := fs.String("env", "", "Current deployment environment to assert against Scope.Environments")
	account := fs.String("account", "", "Current cloud account/tenant ID to assert against Scope.Accounts")
	region := fs.String("region", "", "Current cloud region to assert against Scope.Regions")
	cluster := fs.String("cluster", "", "Current cluster identifier to assert against Scope.Clusters")
	namespace := fs.String("namespace", "", "Current project/group namespace to assert against Scope.Namespaces")
	host := fs.String("host", "", "Current hostname or domain to assert against Scope.Hosts")
	version := fs.String("version", "", "Current running software version to assert (e.g. '1.2.0')")
	buildDateFlag := fs.String("build-date", "", "Software binary build/release date to assert against maintenance window (RFC3339 or YYYY-MM-DD)")
	allowExpired := fs.Bool("allow-expired", false, "Allow signature verification even if license has expired")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *pubKeyPath == "" {
		return fmt.Errorf("-public-key is required")
	}

	resolved, err := license.ResolveLicense(*licenseSource)
	if err != nil {
		return fmt.Errorf("failed to locate license: %w (pass -license or set %s / %s)", err, license.EnvLicenseKey, license.EnvLicenseFile)
	}

	var opts []license.ValidatorOption
	if *product != "" {
		opts = append(opts, license.WithProduct(*product))
	}
	if *fingerprint != "" {
		opts = append(opts, license.WithExpectedFingerprint(*fingerprint))
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
	if *allowExpired {
		opts = append(opts, license.WithAllowExpired(true))
	}

	validator, err := license.NewValidatorFromPEMFile(*pubKeyPath, opts...)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	result, err := validator.VerifyWithResult(resolved.Content)
	if err != nil {
		return fmt.Errorf("VERIFICATION FAILED: %w", err)
	}

	fmt.Println("✓ VERIFICATION SUCCESSFUL: Signature is valid and claims match!")
	if result.VerifiedByKeyID != "" {
		fmt.Printf("🔑 Verified by Key: %s (Status: %s)\n", result.VerifiedByKeyID, result.VerifiedByKeyStatus)
	}
	if resolved.Source != "explicit_file" && resolved.Source != "explicit_token" {
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

	fmt.Println("License Inspection (Unverified Signature):")
	if resolved.Source != "explicit_file" && resolved.Source != "explicit_token" {
		fmt.Printf("ℹ️  Loaded license from: %s\n", resolved.Source)
	}
	fmt.Println("--------------------------------------------------")
	claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println(string(claimsJSON))
	fmt.Println("--------------------------------------------------")
	if claims.IsPerpetual() {
		fmt.Println("Validity: Perpetual (Does not expire)")
	} else if claims.IsInGracePeriod() {
		fmt.Printf("Validity: GRACE PERIOD (%d grace days remaining until %s, initial expiration was %s)\n",
			claims.GraceDaysRemaining(), claims.EffectiveExpiration().Format(time.RFC3339), claims.ExpiresAt.Format(time.RFC3339))
	} else if claims.IsExpired() {
		fmt.Printf("Validity: EXPIRED on %s\n", claims.ExpiresAt.Format(time.RFC3339))
	} else {
		fmt.Printf("Validity: Active (%d days remaining, expires %s)\n", claims.DaysRemaining(), claims.ExpiresAt.Format(time.RFC3339))
	}
	if claims.MaxVersion != "" {
		fmt.Printf("Max Authorized Version: %s\n", claims.MaxVersion)
	}
	if len(claims.AllowedVersions) > 0 {
		fmt.Printf("Allowed Versions: %v\n", claims.AllowedVersions)
	}
	if !claims.MaintenanceExpiresAt.IsZero() {
		fmt.Printf("Maintenance / Updates Cutoff: %s\n", claims.MaintenanceExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func runKeyring(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: license-cli keyring <public-keys-bundle.pem>")
	}
	bundlePath := args[0]
	ring, err := license.NewKeyRingFromPEMFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load keyring bundle: %w", err)
	}

	keys := ring.Keys()
	fmt.Printf("KeyRing Bundle: %s (%d public key(s))\n", bundlePath, len(keys))
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
