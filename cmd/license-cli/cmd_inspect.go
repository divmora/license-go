package main

import (
	"encoding/json"
	"flag"
	"fmt"

	license "github.com/divmora/license-go/pkg/license"
)

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
