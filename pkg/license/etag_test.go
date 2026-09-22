package license

import (
	"testing"
)

func TestCleanETag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
		{"wildcard", "*", "*"},
		{"unquoted hex", "7820133c7f98f59188125cec18d87374", "7820133c7f98f59188125cec18d87374"},
		{"quoted hex", `"7820133c7f98f59188125cec18d87374"`, "7820133c7f98f59188125cec18d87374"},
		{"weak quoted hex", `W/"7820133c7f98f59188125cec18d87374"`, "7820133c7f98f59188125cec18d87374"},
		{"weak lowercase quoted hex", `w/"7820133c7f98f59188125cec18d87374"`, "7820133c7f98f59188125cec18d87374"},
		{"weak unquoted hex", `W/7820133c7f98f59188125cec18d87374`, "7820133c7f98f59188125cec18d87374"},
		{"escaped JSON quotes", `\"7820133c7f98f59188125cec18d87374\"`, "7820133c7f98f59188125cec18d87374"},
		{"double-quoted artifact", `""7820133c7f98f59188125cec18d87374""`, "7820133c7f98f59188125cec18d87374"},
		{"single quotes", `'7820133c7f98f59188125cec18d87374'`, "7820133c7f98f59188125cec18d87374"},
		{"only quotes", `""""`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CleanETag(tc.input)
			if got != tc.expected {
				t.Errorf("CleanETag(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCanonicalETag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
		{"only quotes", `""`, ""},
		{"wildcard", "*", "*"},
		{"unquoted hex", "7820133c", `"7820133c"`},
		{"already quoted", `"7820133c"`, `"7820133c"`},
		{"weak quoted", `W/"7820133c"`, `W/"7820133c"`},
		{"weak lowercase quoted", `w/"7820133c"`, `W/"7820133c"`},
		{"weak unquoted", `W/7820133c`, `W/"7820133c"`},
		{"escaped JSON quotes", `\"7820133c\"`, `"7820133c"`},
		{"double quoted", `""7820133c""`, `"7820133c"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalETag(tc.input)
			if got != tc.expected {
				t.Errorf("CanonicalETag(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestETagsMatch(t *testing.T) {
	tests := []struct {
		name     string
		tag1     string
		tag2     string
		expected bool
	}{
		{"exact strong match", `"abc"`, `"abc"`, true},
		{"strong vs unquoted", `"abc"`, `abc`, true},
		{"strong vs weak", `"abc"`, `W/"abc"`, true},
		{"weak vs weak", `W/"abc"`, `w/"abc"`, true},
		{"escaped vs unquoted", `\"abc\"`, `abc`, true},
		{"mismatch", `"abc"`, `"def"`, false},
		{"wildcard first", "*", `"abc"`, true},
		{"wildcard second", `"abc"`, "*", true},
		{"both empty", "", "", false},
		{"one empty", "", `"abc"`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ETagsMatch(tc.tag1, tc.tag2)
			if got != tc.expected {
				t.Errorf("ETagsMatch(%q, %q) = %v; want %v", tc.tag1, tc.tag2, got, tc.expected)
			}
		})
	}
}

func TestSyncResult_CleanETag(t *testing.T) {
	var nilResult *SyncResult
	if nilResult.CleanETag() != "" {
		t.Errorf("expected empty string for nil SyncResult")
	}

	res := &SyncResult{
		ETag: `W/"7820133c"`,
	}
	if got := res.CleanETag(); got != "7820133c" {
		t.Errorf("expected 7820133c, got %s", got)
	}
}
