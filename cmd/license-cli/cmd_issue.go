package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

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
