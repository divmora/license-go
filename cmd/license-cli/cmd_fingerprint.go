package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

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
