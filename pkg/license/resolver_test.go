package license

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLicense_ExplicitFile(t *testing.T) {
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "license.key")
	expectedContent := "DIV1.explicit-file-content.signature"

	if err := os.WriteFile(licFile, []byte(expectedContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	resolved, err := ResolveLicense(licFile)
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}

	if resolved.Content != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, resolved.Content)
	}
	if resolved.FilePath != licFile {
		t.Errorf("expected filePath %q, got %q", licFile, resolved.FilePath)
	}
	if resolved.Source != "explicit_file" {
		t.Errorf("expected source explicit_file, got %q", resolved.Source)
	}
}

func TestResolveLicense_ExplicitTokenString(t *testing.T) {
	compact := "DIV1.inline-token-payload.signature"
	resolved, err := ResolveLicense(compact)
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	if resolved.Content != compact {
		t.Errorf("expected %q, got %q", compact, resolved.Content)
	}
	if resolved.FilePath != "" {
		t.Errorf("expected empty filePath for inline token, got %q", resolved.FilePath)
	}
	if resolved.Source != "explicit_token" {
		t.Errorf("expected source explicit_token, got %q", resolved.Source)
	}

	armored := "-----BEGIN DIVMORA LICENSE KEY-----\nDIV1.payload.sig\n-----END DIVMORA LICENSE KEY-----"
	resolvedArmored, err := ResolveLicense(armored)
	if err != nil {
		t.Fatalf("ResolveLicense failed on armored: %v", err)
	}
	if resolvedArmored.Content != armored {
		t.Errorf("expected armored content, got %q", resolvedArmored.Content)
	}
	if resolvedArmored.Source != "explicit_token" {
		t.Errorf("expected source explicit_token, got %q", resolvedArmored.Source)
	}
}

func TestResolveLicense_ExplicitMissingFile(t *testing.T) {
	_, err := ResolveLicense("/path/does/not/exist/license.key")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist error, got %v", err)
	}
}

func TestResolveLicense_EnvLicenseKey(t *testing.T) {
	expectedToken := "DIV1.env-token.sig"
	t.Setenv(EnvLicenseKey, expectedToken)
	t.Setenv(EnvLicenseFile, "")

	resolved, err := ResolveLicense()
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	if resolved.Content != expectedToken {
		t.Errorf("expected content %q, got %q", expectedToken, resolved.Content)
	}
	if resolved.Source != "env:"+EnvLicenseKey {
		t.Errorf("expected source env:%s, got %q", EnvLicenseKey, resolved.Source)
	}

	// Test ResolveToken helper
	token, err := ResolveToken()
	if err != nil || token != expectedToken {
		t.Errorf("ResolveToken() = (%q, %v), want (%q, nil)", token, err, expectedToken)
	}
}

func TestResolveLicense_EnvLicenseFile(t *testing.T) {
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "env-license.key")
	expectedContent := "DIV1.from-env-file.sig"

	if err := os.WriteFile(licFile, []byte(expectedContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicenseFile, licFile)

	resolved, err := ResolveLicense()
	if err != nil {
		t.Fatalf("ResolveLicense failed: %v", err)
	}
	if resolved.Content != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, resolved.Content)
	}
	if resolved.FilePath != licFile {
		t.Errorf("expected filePath %q, got %q", licFile, resolved.FilePath)
	}
	if resolved.Source != "env:"+EnvLicenseFile {
		t.Errorf("expected source env:%s, got %q", EnvLicenseFile, resolved.Source)
	}
}

func TestResolveLicense_NotFound(t *testing.T) {
	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicenseFile, "")

	// On non-standard path without default /etc/divmora/license.key
	// (or if /etc/divmora/license.key does not exist)
	if _, err := os.Stat(DefaultLicensePath); os.IsNotExist(err) {
		_, err := ResolveLicense()
		if !errors.Is(err, ErrLicenseNotFound) {
			t.Fatalf("expected ErrLicenseNotFound, got %v", err)
		}
	}
}

func TestResolveLicense_MultiArgumentOrder(t *testing.T) {
	tempDir := t.TempDir()
	licFile := filepath.Join(tempDir, "company.key")
	fileContent := "DIV1.file-token.signature"
	if err := os.WriteFile(licFile, []byte(fileContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	inlineToken := "DIV1.inline-token.signature"

	// 1. ResolveToken("", licFile) -> must inspect second argument and return file content
	token, err := ResolveToken("", licFile)
	if err != nil {
		t.Fatalf("ResolveToken('', licFile) failed: %v", err)
	}
	if token != fileContent {
		t.Errorf("expected fileContent %q, got %q", fileContent, token)
	}

	// 2. ResolveToken(inlineToken, licFile) -> must prefer first non-empty argument
	tokenFirst, err := ResolveToken(inlineToken, licFile)
	if err != nil {
		t.Fatalf("ResolveToken(inlineToken, licFile) failed: %v", err)
	}
	if tokenFirst != inlineToken {
		t.Errorf("expected inlineToken %q, got %q", inlineToken, tokenFirst)
	}

	// 3. ResolveToken("", "") -> falls back to env
	t.Setenv(EnvLicenseKey, inlineToken)
	tokenEnv, err := ResolveToken("", "")
	if err != nil {
		t.Fatalf("ResolveToken('', '') fallback failed: %v", err)
	}
	if tokenEnv != inlineToken {
		t.Errorf("expected env inlineToken %q, got %q", inlineToken, tokenEnv)
	}

	// 4. ResolveToken("", "/nonexistent/path.key") -> must fail with os.ErrNotExist
	_, err = ResolveToken("", "/nonexistent/path.key")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}
