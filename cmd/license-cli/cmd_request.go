package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

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
