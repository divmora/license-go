package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/divmora/license-go/internal/issuer"
	"github.com/divmora/license-go/pkg/license"
)

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

	pub, priv, err := issuer.GenerateKeyPair()
	if err != nil {
		return err
	}

	privPath := filepath.Join(*outDir, *privName)
	pubPath := filepath.Join(*outDir, *pubName)

	if err := issuer.SavePrivateKeyToPEMFile(priv, privPath, 0600); err != nil {
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
