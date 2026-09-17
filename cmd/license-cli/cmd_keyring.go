package main

import (
	"fmt"

	license "github.com/divmora/license-go/pkg/license"
)

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
