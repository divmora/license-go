package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	license "github.com/divmora/license-go/pkg/license"
)

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
