package license

import (
	"fmt"
	"strings"
)

// CleanETag extracts the clean, unquoted opaque identifier from an HTTP ETag.
// It strips any weak prefix ("W/" or "w/"), leading/trailing double or single quotes,
// and escaped quote artifacts.
func CleanETag(etag string) string {
	etag = strings.TrimSpace(etag)
	if etag == "" || etag == "*" {
		return etag
	}

	// Strip weak prefix if present
	if strings.HasPrefix(strings.ToLower(etag), "w/") {
		etag = etag[2:]
	}

	// Strip escaped backslashes (e.g. \" from JSON artifacts)
	etag = strings.ReplaceAll(etag, `\`, "")

	// Strip surrounding double quotes or single quotes
	etag = strings.Trim(etag, "\"'")

	return strings.TrimSpace(etag)
}

// CanonicalETag formats an HTTP entity-tag strictly conforming to RFC 7232 Section 2.3.
// It ensures that entity-tags transmitted in conditional headers (such as If-None-Match or If-Match)
// are properly enclosed in double quotes (e.g. "opaque-tag" or W/"opaque-tag").
// If the input tag is empty, it returns an empty string.
// If the input tag is the wildcard "*", it returns "*".
func CanonicalETag(etag string) string {
	etag = strings.TrimSpace(etag)
	if etag == "" || etag == "*" {
		return etag
	}

	isWeak := strings.HasPrefix(strings.ToLower(etag), "w/")
	clean := CleanETag(etag)
	if clean == "" {
		return ""
	}

	if isWeak {
		return fmt.Sprintf(`W/"%s"`, clean)
	}
	return fmt.Sprintf(`"%s"`, clean)
}

// ETagsMatch performs an RFC 7232 weak comparison between two entity-tags.
// Under RFC 7232 Section 2.3.2, two entity-tags match under weak comparison
// if their opaque tags match character-for-character, regardless of weak validators.
// Returns true if either tag is the wildcard "*" (and both are non-empty),
// or if both clean opaque tags are identical.
func ETagsMatch(etag1, etag2 string) bool {
	clean1 := CleanETag(etag1)
	clean2 := CleanETag(etag2)

	if clean1 == "" || clean2 == "" {
		return false
	}

	if clean1 == "*" || clean2 == "*" {
		return true
	}

	return clean1 == clean2
}

// CleanETag returns the HTTP entity tag without surrounding quotes or weak "W/" prefix.
func (r *SyncResult) CleanETag() string {
	if r == nil {
		return ""
	}
	return CleanETag(r.ETag)
}
