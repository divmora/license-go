package license

import (
	"fmt"
	"os"
	"strings"
)

const (
	// EnvLicenseKey is the environment variable containing the raw compact token or armored PEM block.
	EnvLicenseKey = "DIVMORA_LICENSE_KEY"

	// EnvLicenseFile is the environment variable containing the path to a license file on disk.
	EnvLicenseFile = "DIVMORA_LICENSE_FILE"

	// DefaultLicensePath is the standard Linux/container filesystem path for Divmora licenses.
	DefaultLicensePath = "/etc/divmora/license.key"
)

// ResolvedLicense contains the resolved license contents and origin metadata.
type ResolvedLicense struct {
	// Content contains the raw compact token or armored PEM block text.
	Content string

	// FilePath is non-empty if the license was resolved from a file on disk (enabling hot-reloading).
	FilePath string

	// Source identifies how the license was located (e.g., "explicit_file", "explicit_token", "env:DIVMORA_LICENSE_KEY", "env:DIVMORA_LICENSE_FILE", "default_file").
	Source string
}

// ResolveLicense locates and reads a Divmora license following a standardized resolution hierarchy:
//  1. Explicit source argument (if provided and non-empty):
//     - If it points to an existing file, reads the file content (populating FilePath).
//     - If it starts with "DIV1." or "-----BEGIN", treats it as an inline token string.
//     - If it is neither, returns a file not found error.
//  2. DIVMORA_LICENSE_KEY environment variable (raw token or armored text string).
//  3. DIVMORA_LICENSE_FILE environment variable (path to license file on disk).
//  4. Default system license path (/etc/divmora/license.key) if it exists.
//  5. If none of the above succeed, returns ErrLicenseNotFound.
func ResolveLicense(explicitSource ...string) (*ResolvedLicense, error) {
	// 1. Check explicit source arguments in order
	for _, rawSrc := range explicitSource {
		src := strings.TrimSpace(rawSrc)
		if src == "" {
			continue
		}

		if fi, err := os.Stat(src); err == nil && !fi.IsDir() {
			data, err := os.ReadFile(src)
			if err != nil {
				return nil, fmt.Errorf("failed to read license file %s: %w", src, err)
			}
			return &ResolvedLicense{
				Content:  string(data),
				FilePath: src,
				Source:   "explicit_file",
			}, nil
		}

		if strings.HasPrefix(src, VersionPrefix+".") || strings.Contains(src, ArmoredHeader) {
			return &ResolvedLicense{
				Content:  src,
				FilePath: "",
				Source:   "explicit_token",
			}, nil
		}

		return nil, fmt.Errorf("license file %q not found: %w", src, os.ErrNotExist)
	}

	// 2. Check DIVMORA_LICENSE_KEY environment variable
	if envKey := strings.TrimSpace(os.Getenv(EnvLicenseKey)); envKey != "" {
		return &ResolvedLicense{
			Content:  envKey,
			FilePath: "",
			Source:   "env:" + EnvLicenseKey,
		}, nil
	}

	// 3. Check DIVMORA_LICENSE_FILE environment variable
	if envFile := strings.TrimSpace(os.Getenv(EnvLicenseFile)); envFile != "" {
		data, err := os.ReadFile(envFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read license file from %s (%s): %w", EnvLicenseFile, envFile, err)
		}
		return &ResolvedLicense{
			Content:  string(data),
			FilePath: envFile,
			Source:   "env:" + EnvLicenseFile,
		}, nil
	}

	// 4. Check DefaultLicensePath (/etc/divmora/license.key)
	if fi, err := os.Stat(DefaultLicensePath); err == nil && !fi.IsDir() {
		data, err := os.ReadFile(DefaultLicensePath)
		if err == nil {
			return &ResolvedLicense{
				Content:  string(data),
				FilePath: DefaultLicensePath,
				Source:   "default_file",
			}, nil
		}
	}

	return nil, ErrLicenseNotFound
}

// ResolveToken returns the license token content string using the standard resolution hierarchy.
func ResolveToken(explicitSource ...string) (string, error) {
	resolved, err := ResolveLicense(explicitSource...)
	if err != nil {
		return "", err
	}
	return resolved.Content, nil
}
