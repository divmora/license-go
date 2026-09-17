package helpers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainsCaseInsensitive(t *testing.T) {
	slice := []string{"Production", "Staging", "DEVELOPMENT"}
	tests := []struct {
		target string
		want   bool
	}{
		{"production", true},
		{"PRODUCTION", true},
		{"staging", true},
		{"development", true},
		{"dev", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := ContainsCaseInsensitive(slice, tc.target); got != tc.want {
			t.Errorf("ContainsCaseInsensitive(%v, %q) = %v, want %v", slice, tc.target, got, tc.want)
		}
	}
}

func TestCleanVersionString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"v1.2.3", "1.2.3"},
		{"V2.0.0", "2.0.0"},
		{" 1.0.0 ", "1.0.0"},
		{"", ""},
	}

	for _, tc := range tests {
		if got := CleanVersionString(tc.in); got != tc.want {
			t.Errorf("CleanVersionString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeSemVerString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"1", "1.0.0"},
		{"1.2", "1.2.0"},
		{"1.2.3", "1.2.3"},
		{"1-beta", "1.0.0-beta"},
		{"*", "*"},
		{"", ""},
	}

	for _, tc := range tests {
		if got := NormalizeSemVerString(tc.in); got != tc.want {
			t.Errorf("NormalizeSemVerString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReplaceWildcardSegments(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"1.x", "1.*"},
		{"1.X.0", "1.*.0"},
		{"1.0.fix", "1.0.fix"},
	}

	for _, tc := range tests {
		if got := ReplaceWildcardSegments(tc.in); got != tc.want {
			t.Errorf("ReplaceWildcardSegments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMatchVersionPattern(t *testing.T) {
	tests := []struct {
		pattern string
		version string
		want    bool
	}{
		{"*", "1.2.3", true},
		{"all", "2.0.0", true},
		{"1.*", "1.4.2", true},
		{"1.x", "1.5.0", true},
		{"1.2.*", "1.2.9", true},
		{"1.2.*", "1.3.0", false},
		{"v1.2.3", "1.2.3", true},
		{"2.0.0", "1.9.9", false},
	}

	for _, tc := range tests {
		if got := MatchVersionPattern(tc.pattern, tc.version); got != tc.want {
			t.Errorf("MatchVersionPattern(%q, %q) = %v, want %v", tc.pattern, tc.version, got, tc.want)
		}
	}
}

func TestCompareSemVer(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
		ok     bool
	}{
		{"1.0.0", "2.0.0", -1, true},
		{"2.0.0", "1.0.0", 1, true},
		{"1.2.3", "1.2.3", 0, true},
		{"invalid", "1.0.0", 0, false},
	}

	for _, tc := range tests {
		got, ok := CompareSemVer(tc.v1, tc.v2)
		if ok != tc.ok || got != tc.want {
			t.Errorf("CompareSemVer(%q, %q) = (%v, %v), want (%v, %v)", tc.v1, tc.v2, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCheckMaxVersion(t *testing.T) {
	tests := []struct {
		maxVersion string
		version    string
		want       bool
	}{
		{"2.0.0", "1.9.0", true},
		{"2.0.0", "2.0.0", true},
		{"2.0.0", "2.0.1", false},
		{"<2.0.0", "2.0.0", false},
		{"<2.0.0", "1.9.9", true},
		{"<=2.0.0", "2.0.0", true},
		{"1.*", "1.99.99", true},
		{"1.*", "2.0.0", false},
		{"1.2.*", "1.2.9", true},
		{"1.2.*", "1.3.0", false},
		{"*", "9.9.9", true},
	}

	for _, tc := range tests {
		if got := CheckMaxVersion(tc.maxVersion, tc.version); got != tc.want {
			t.Errorf("CheckMaxVersion(%q, %q) = %v, want %v", tc.maxVersion, tc.version, got, tc.want)
		}
	}
}

func TestConstantTimeFingerprintMatch(t *testing.T) {
	if !ConstantTimeFingerprintMatch("abc", "ABC") {
		t.Errorf("expected match for 'abc' and 'ABC'")
	}
	if ConstantTimeFingerprintMatch("abc", "def") {
		t.Errorf("unexpected match for 'abc' and 'def'")
	}
	if ConstantTimeFingerprintMatch("", "abc") {
		t.Errorf("empty string should not match")
	}
}

func TestGenerateRandomID(t *testing.T) {
	id1, err := GenerateRandomID()
	if err != nil {
		t.Fatalf("GenerateRandomID failed: %v", err)
	}
	id2, err := GenerateRandomID()
	if err != nil {
		t.Fatalf("GenerateRandomID failed: %v", err)
	}
	if len(id1) != 32 { // 16 bytes hex = 32 chars
		t.Errorf("expected 32 chars hex, got %d", len(id1))
	}
	if id1 == id2 {
		t.Errorf("random IDs collided: %s == %s", id1, id2)
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"alice@example.com", true},
		{"bob.smith+tag@sub.domain.co", true},
		{"invalid", false},
		{"@domain.com", false},
		{"user@", false},
		{"user@domain", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := IsValidEmail(tc.email); got != tc.want {
			t.Errorf("IsValidEmail(%q) = %v, want %v", tc.email, got, tc.want)
		}
	}
}

func TestResolveEnvFromProcess(t *testing.T) {
	os.Unsetenv("DIVMORA_ENV")
	os.Unsetenv("DIVMORA_ENVIRONMENT")

	if got := ResolveEnvFromProcess(); got != "" {
		t.Errorf("expected empty env, got %q", got)
	}

	os.Setenv("DIVMORA_ENVIRONMENT", "staging")
	if got := ResolveEnvFromProcess(); got != "staging" {
		t.Errorf("expected 'staging', got %q", got)
	}

	os.Setenv("DIVMORA_ENV", "production")
	if got := ResolveEnvFromProcess(); got != "production" {
		t.Errorf("expected 'production', got %q", got)
	}

	os.Unsetenv("DIVMORA_ENV")
	os.Unsetenv("DIVMORA_ENVIRONMENT")
}

func TestFilesHelper(t *testing.T) {
	tmpDir := t.TempDir()
	normalFile := filepath.Join(tmpDir, "normal.txt")
	if err := os.WriteFile(normalFile, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}

	symlinkFile := filepath.Join(tmpDir, "symlink.txt")
	if err := os.Symlink(normalFile, symlinkFile); err != nil {
		t.Fatal(err)
	}

	// Normal file should succeed
	data, err := SafeReadFile(normalFile)
	if err != nil || string(data) != "hello world" {
		t.Errorf("SafeReadFile(normalFile) failed: %v, data=%q", err, string(data))
	}

	// Symlink should be rejected
	_, err = SafeReadFile(symlinkFile)
	if err == nil {
		t.Errorf("expected error for symlink, got nil")
	}
}
