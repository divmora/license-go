package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/divmora/license-go/internal/issuer"
	license "github.com/divmora/license-go/pkg/license"
)

func runSignCRL(args []string) error {
	fs := flag.NewFlagSet("crl sign", flag.ExitOnError)
	privKeyPath := fs.String("private-key", "", "Path to Ed25519 private key PEM file (required)")
	crlID := fs.String("id", "", "Unique CRL identifier (generated if omitted)")
	issuerName := fs.String("issuer", "divmora.com/crl", "Issuing authority name")
	product := fs.String("product", "", "Product scope restriction (empty for all products)")
	keyID := fs.String("key-id", "", "Signing Key ID hint")
	nextUpdateFlag := fs.String("next-update", "", "CRL expiration/next update timestamp (RFC3339, YYYY-MM-DD, or duration e.g. '30d')")
	entriesFlag := fs.String("entries", "", "Revoked license IDs: 'id1=reason,id2=reason' or 'id1,id2'")
	entriesFile := fs.String("entries-file", "", "Path to JSON or text file containing revoked entries")
	metaFlag := fs.String("meta", "", "Custom metadata key-value pairs (k=v,k2=v2)")
	armored := fs.Bool("armored", true, "Output armored PEM block")
	outFile := fs.String("out", "", "Output file path (prints to stdout if omitted)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *privKeyPath == "" {
		return errors.New("private key required: pass -private-key <path>")
	}

	privKeyPEM, err := os.ReadFile(*privKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	privKey, err := issuer.ParsePrivateKeyFromPEM(privKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	now := time.Now().UTC()

	id := strings.TrimSpace(*crlID)
	if id == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id = fmt.Sprintf("crl-%s-%s", now.Format("20060102"), hex.EncodeToString(b))
	}

	var nextUpdate time.Time
	if *nextUpdateFlag != "" {
		val := strings.TrimSpace(*nextUpdateFlag)
		if strings.HasSuffix(val, "d") || strings.HasSuffix(val, "D") {
			daysStr := strings.TrimRight(val, "dD")
			var days int
			if _, err := fmt.Sscanf(daysStr, "%d", &days); err == nil && days > 0 {
				nextUpdate = now.AddDate(0, 0, days)
			}
		}
		if nextUpdate.IsZero() {
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				nextUpdate = t.UTC()
			} else if t, err := time.Parse("2006-01-02", val); err == nil {
				nextUpdate = t.UTC()
			} else if d, err := time.ParseDuration(val); err == nil {
				nextUpdate = now.Add(d)
			} else {
				return fmt.Errorf("invalid -next-update %q: expected RFC3339, YYYY-MM-DD, or duration (e.g. 30d, 720h)", val)
			}
		}
	}

	var entries []license.RevocationEntry
	if *entriesFile != "" {
		fileEntries, err := loadEntriesFromFile(*entriesFile)
		if err != nil {
			return fmt.Errorf("failed to load entries from file: %w", err)
		}
		entries = append(entries, fileEntries...)
	}

	if *entriesFlag != "" {
		cliEntries := parseEntriesFlag(*entriesFlag, now)
		entries = append(entries, cliEntries...)
	}

	meta := parseMetadata(*metaFlag)

	claims := license.RevocationListClaims{
		ID:         id,
		Issuer:     *issuerName,
		Product:    *product,
		KeyID:      *keyID,
		IssuedAt:   now,
		NextUpdate: nextUpdate,
		Entries:    entries,
		Metadata:   meta,
	}

	var opts []license.SignCRLOption
	if *keyID != "" {
		opts = append(opts, license.WithCRLSignerKeyID(*keyID))
	}

	var output string
	if *armored {
		out, err := license.SignCRLArmored(claims, privKey, opts...)
		if err != nil {
			return fmt.Errorf("failed to sign armored CRL: %w", err)
		}
		output = out
	} else {
		out, err := license.SignCRL(claims, privKey, opts...)
		if err != nil {
			return fmt.Errorf("failed to sign CRL token: %w", err)
		}
		output = out
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write CRL output to %s: %w", *outFile, err)
		}
		fmt.Printf("✓ Successfully minted Certificate Revocation List (CRL):\n")
		fmt.Printf("  CRL ID:     %s\n", claims.ID)
		fmt.Printf("  Revoked:    %d licenses\n", len(claims.Entries))
		fmt.Printf("  Output:     %s\n", *outFile)
		return nil
	}

	fmt.Print(output)
	return nil
}

func parseEntriesFlag(raw string, defaultTime time.Time) []license.RevocationEntry {
	var res []license.RevocationEntry
	items := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		entry := license.RevocationEntry{
			ID:        strings.TrimSpace(parts[0]),
			RevokedAt: defaultTime,
		}
		if len(parts) == 2 {
			entry.Reason = strings.TrimSpace(parts[1])
		}
		res = append(res, entry)
	}
	return res
}

func loadEntriesFromFile(filePath string) ([]license.RevocationEntry, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Try JSON format first
	var jsonEntries []license.RevocationEntry
	if err := json.Unmarshal(data, &jsonEntries); err == nil && len(jsonEntries) > 0 {
		return jsonEntries, nil
	}

	// Otherwise parse line by line (id=reason or id)
	now := time.Now().UTC()
	var entries []license.RevocationEntry
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		entry := license.RevocationEntry{
			ID:        strings.TrimSpace(parts[0]),
			RevokedAt: now,
		}
		if len(parts) == 2 {
			entry.Reason = strings.TrimSpace(parts[1])
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func runVerifyCRL(args []string) error {
	fs := flag.NewFlagSet("crl verify", flag.ExitOnError)
	pubKeyPath := fs.String("public-key", "", "Path to public key PEM or PEM bundle file (optional; falls back to DIVMORA_PUBLIC_KEY/DIVMORA_PUBLIC_KEYS_PEM)")
	crlSource := fs.String("crl", "", "Path to CRL file or raw token (optional; falls back to DIVMORA_CRL/DIVMORA_CRL_FILE)")

	if err := fs.Parse(args); err != nil {
		return err
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
			return fmt.Errorf("public verification key required: %w", err)
		}
		ring = resolvedKey.KeyRing
	}

	var rawCRL string
	if *crlSource != "" {
		if data, err := os.ReadFile(*crlSource); err == nil {
			rawCRL = string(data)
		} else {
			rawCRL = *crlSource
		}
	} else {
		res, err := license.ResolveCRL()
		if err != nil {
			return fmt.Errorf("crl required: pass -crl <path> or set %s: %w", license.EnvCRLFile, err)
		}
		rawCRL = res.Content
	}

	claims, keyEntry, err := license.VerifyCRL(rawCRL, ring)
	if err != nil {
		return fmt.Errorf("CRL VERIFICATION FAILED: %w", err)
	}

	fmt.Println("✓ CERTIFICATE REVOCATION LIST VERIFIED: Signature and format are valid!")
	fmt.Printf("CRL ID:        %s\n", claims.ID)
	if claims.Issuer != "" {
		fmt.Printf("Issuer:        %s\n", claims.Issuer)
	}
	if claims.Product != "" {
		fmt.Printf("Product:       %s\n", claims.Product)
	}
	fmt.Printf("Issued At:     %s\n", claims.IssuedAt.Format(time.RFC3339))
	if !claims.NextUpdate.IsZero() {
		expired := claims.IsExpiredAt(time.Now())
		status := "Active"
		if expired {
			status = "EXPIRED"
		}
		fmt.Printf("Next Update:   %s (%s)\n", claims.NextUpdate.Format(time.RFC3339), status)
	}
	fmt.Printf("Revoked Count: %d\n", claims.Count())
	if keyEntry != nil {
		fmt.Printf("Verified By:   %s (Status: %s)\n", keyEntry.ID, keyEntry.Status)
	}
	return nil
}

func runInspectCRL(args []string) error {
	fs := flag.NewFlagSet("crl inspect", flag.ExitOnError)
	crlSource := fs.String("crl", "", "Path to CRL file or raw token (optional; falls back to DIVMORA_CRL/DIVMORA_CRL_FILE)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var rawCRL string
	if *crlSource != "" {
		if data, err := os.ReadFile(*crlSource); err == nil {
			rawCRL = string(data)
		} else {
			rawCRL = *crlSource
		}
	} else {
		res, err := license.ResolveCRL()
		if err != nil {
			return fmt.Errorf("crl required: pass -crl <path> or set %s: %w", license.EnvCRLFile, err)
		}
		rawCRL = res.Content
	}

	claims, err := license.InspectCRL(rawCRL)
	if err != nil {
		return fmt.Errorf("failed to inspect CRL: %w", err)
	}

	fmt.Print(claims.FormatInspect())
	return nil
}

func runCheckCRL(args []string) error {
	fs := flag.NewFlagSet("crl check", flag.ExitOnError)
	crlSource := fs.String("crl", "", "Path to CRL file or raw token (required)")
	licenseID := fs.String("id", "", "License ID (UUID) to test for revocation (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *licenseID == "" {
		return errors.New("license ID required: pass -id <license-id>")
	}

	var rawCRL string
	if *crlSource != "" {
		if data, err := os.ReadFile(*crlSource); err == nil {
			rawCRL = string(data)
		} else {
			rawCRL = *crlSource
		}
	} else {
		res, err := license.ResolveCRL()
		if err != nil {
			return fmt.Errorf("crl required: pass -crl <path>: %w", err)
		}
		rawCRL = res.Content
	}

	claims, err := license.InspectCRL(rawCRL)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	if entry, revoked := claims.IsRevoked(*licenseID); revoked {
		fmt.Printf("✗ REVOKED: License %q IS REVOKED in CRL %s\n", *licenseID, claims.ID)
		if !entry.RevokedAt.IsZero() {
			fmt.Printf("  Revocation Date: %s\n", entry.RevokedAt.Format(time.RFC3339))
		}
		if entry.Reason != "" {
			fmt.Printf("  Reason:          %s\n", entry.Reason)
		}
		return errors.New("license is revoked")
	}

	fmt.Printf("✓ ACTIVE: License %q is NOT revoked in CRL %s (%d total entries)\n",
		*licenseID, claims.ID, claims.Count())
	return nil
}

func runSyncCRL(args []string) error {
	fs := flag.NewFlagSet("crl sync", flag.ExitOnError)
	urlFlag := fs.String("url", "", "Remote CRL distribution URL (optional; falls back to DIVMORA_CRL_URL or default CDN endpoint)")
	product := fs.String("product", "", "Expected product name to scope the CRL and resolve default URL")
	pubKeyPath := fs.String("public-key", "", "Path to Ed25519 public key file or base64 key string (optional; auto-resolves via environment)")
	outFile := fs.String("out", "", "Output path to write downloaded CRL token (prints to stdout if omitted)")
	cacheFile := fs.String("cache-file", "", "Local cache file path for offline/air-gap fallback (optional)")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "HTTP timeout duration (e.g. 10s)")
	strictExpiry := fs.Bool("strict-expiry", false, "Reject CRL if past NextUpdate")
	verbose := fs.Bool("verbose", false, "Print detailed synchronization diagnostics")

	if err := fs.Parse(args); err != nil {
		return err
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

	resolvedURL := license.ResolveCRLURL(*product, *urlFlag)
	resolvedCache := *cacheFile
	if resolvedCache == "" {
		resolvedCache = license.ResolveCRLCacheFile()
	}

	syncer, err := license.NewCRLSyncer(license.CRLSyncConfig{
		URL:             resolvedURL,
		KeyRing:         ring,
		CacheFile:       resolvedCache,
		Timeout:         *timeoutFlag,
		StrictExpiry:    *strictExpiry,
		ExpectedProduct: *product,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize crl syncer: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag+5*time.Second)
	defer cancel()

	result, err := syncer.Sync(ctx)
	if err != nil {
		return fmt.Errorf("crl synchronization failed: %w", err)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(syncer.Raw()), 0644); err != nil {
			return fmt.Errorf("failed to write output crl to %s: %w", *outFile, err)
		}
	}

	claims := result.Claims
	fmt.Printf("✓ CRL synchronized successfully (%s)\n", result.Source)
	fmt.Printf("  CRL ID:          %s\n", claims.ID)
	if claims.Issuer != "" {
		fmt.Printf("  Issuer:          %s\n", claims.Issuer)
	}
	if claims.Product != "" {
		fmt.Printf("  Product Scope:   %s\n", claims.Product)
	}
	if !claims.NextUpdate.IsZero() {
		fmt.Printf("  Next Update:     %s\n", claims.NextUpdate.UTC().Format(time.RFC3339))
	}
	fmt.Printf("  Revoked Entries: %d\n", claims.Count())
	if resolvedCache != "" {
		fmt.Printf("  Local Cache:     %s\n", resolvedCache)
	}

	if *verbose {
		fmt.Println()
		if result.ETag != "" {
			fmt.Printf("  HTTP ETag:       %s\n", result.ETag)
		}
		if result.LastModified != "" {
			fmt.Printf("  Last-Modified:   %s\n", result.LastModified)
		}
		if result.NetworkError != nil {
			fmt.Printf("  Network Warning: %v (used cache fallback)\n", result.NetworkError)
		}
	}

	if *outFile == "" && !*verbose {
		fmt.Println()
		fmt.Println(syncer.Raw())
	}

	return nil
}
