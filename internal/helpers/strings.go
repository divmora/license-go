package helpers

import (
	"path"
	"strconv"
	"strings"
)

// ContainsCaseInsensitive reports whether target matches any element in slice,
// ignoring case and trimming leading/trailing whitespace.
func ContainsCaseInsensitive(slice []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, item := range slice {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

// CleanVersionString strips leading 'v' or 'V' and trims whitespace from a version string.
func CleanVersionString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	return s
}

// NormalizeSemVerString pads a short version string (e.g. "1" -> "1.0.0", "1.2" -> "1.2.0")
// while preserving pre-release tags (e.g. "1-beta" -> "1.0.0-beta").
func NormalizeSemVerString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	pre := ""
	if idx := strings.IndexAny(s, "-+"); idx != -1 {
		pre = s[idx:]
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 1:
		if parts[0] != "" && parts[0] != "*" {
			s = parts[0] + ".0.0"
		}
	case 2:
		if parts[1] != "*" {
			s = parts[0] + "." + parts[1] + ".0"
		}
	}
	return s + pre
}

// ReplaceWildcardSegments converts standalone 'x' or 'X' segments (e.g. "1.x", "1.X.0") to '*'
// without altering non-wildcard occurrences of 'x' inside words (e.g. "1.0.fix").
func ReplaceWildcardSegments(versionStr string) string {
	segments := strings.Split(versionStr, ".")
	for i, seg := range segments {
		if seg == "x" || seg == "X" {
			segments[i] = "*"
		}
	}
	return strings.Join(segments, ".")
}

// MatchVersionPattern checks if a target version matches a pattern.
// Supported patterns:
//   - "*" or "all": matches any version
//   - "1.*", "v1.*", "1.x": matches any minor/patch in major 1
//   - "1.2.*", "1.2.x": matches any patch in 1.2
//   - exact match: "1.2.3" or "v1.2.3"
func MatchVersionPattern(pattern, version string) bool {
	p := CleanVersionString(pattern)
	v := CleanVersionString(version)

	if p == "*" || p == "all" {
		return true
	}
	if p == v {
		return true
	}

	normV := NormalizeSemVerString(v)
	normP := NormalizeSemVerString(p)
	if normP == normV || p == normV {
		return true
	}

	// Convert standalone segment "x" or "X" to "*"
	p = ReplaceWildcardSegments(p)

	if strings.Contains(p, "*") {
		if matched, err := path.Match(p, normV); err == nil && matched {
			return true
		}
		if matched, err := path.Match(p, v); err == nil && matched {
			return true
		}
	}

	return false
}

// ParseSemVer extracts major, minor, patch numbers from a version string.
func ParseSemVer(s string) (major, minor, patch int, ok bool) {
	s = CleanVersionString(s)
	// Strip pre-release or build metadata: 1.2.3-rc1 -> 1.2.3
	if idx := strings.IndexAny(s, "-+"); idx != -1 {
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) == 0 {
		return 0, 0, 0, false
	}

	var err error
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}

	if len(parts) > 1 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return major, 0, 0, true
		}
	}

	if len(parts) > 2 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return major, minor, 0, true
		}
	}

	return major, minor, patch, true
}

// CompareSemVer compares two semver strings:
// returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareSemVer(v1, v2 string) (int, bool) {
	maj1, min1, pat1, ok1 := ParseSemVer(v1)
	maj2, min2, pat2, ok2 := ParseSemVer(v2)
	if !ok1 || !ok2 {
		return 0, false
	}

	if maj1 != maj2 {
		if maj1 < maj2 {
			return -1, true
		}
		return 1, true
	}

	if min1 != min2 {
		if min1 < min2 {
			return -1, true
		}
		return 1, true
	}

	if pat1 != pat2 {
		if pat1 < pat2 {
			return -1, true
		}
		return 1, true
	}

	return 0, true
}

// CheckMaxVersion asserts that version does not exceed maxVersion.
// Supports:
//   - "<=2.5.0", "<=2.5", "2.5.0"
//   - "<2.5.0", "<2.5"
//   - "1.*", "1.x" (allows any version with major <= 1)
//   - "1.2.*", "1.2.x" (allows any version with major < 1 || (major == 1 && minor <= 2))
func CheckMaxVersion(maxVersion, version string) bool {
	maxClean := strings.TrimSpace(maxVersion)
	isStrictLess := false
	if strings.HasPrefix(maxClean, "<=") {
		maxClean = strings.TrimSpace(strings.TrimPrefix(maxClean, "<="))
	} else if strings.HasPrefix(maxClean, "<") {
		isStrictLess = true
		maxClean = strings.TrimSpace(strings.TrimPrefix(maxClean, "<"))
	}
	maxClean = CleanVersionString(maxClean)
	vClean := CleanVersionString(version)

	if maxClean == "*" || maxClean == "all" {
		return true
	}

	vMajor, vMinor, _, vOk := ParseSemVer(vClean)
	if !vOk {
		return false
	}

	// Normalize wildcards: replace standalone 'x' or 'X' segments with '*'
	normalizedMax := ReplaceWildcardSegments(maxClean)

	// If maxVersion contains wildcard '*'
	if strings.Contains(normalizedMax, "*") {
		parts := strings.Split(normalizedMax, ".")
		if len(parts) == 1 {
			return true
		}

		// Major only wildcard, e.g. "1.*"
		if len(parts) >= 2 && parts[1] == "*" {
			pMajor, err := strconv.Atoi(parts[0])
			if err == nil {
				if isStrictLess {
					return vMajor < pMajor
				}
				return vMajor <= pMajor
			}
		}

		// Major.Minor wildcard, e.g. "1.2.*"
		if len(parts) >= 3 && parts[2] == "*" {
			pMajor, err1 := strconv.Atoi(parts[0])
			pMinor, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil {
				if isStrictLess {
					if vMajor < pMajor {
						return true
					}
					if vMajor == pMajor && vMinor < pMinor {
						return true
					}
					return false
				}
				if vMajor < pMajor {
					return true
				}
				if vMajor == pMajor && vMinor <= pMinor {
					return true
				}
				return false
			}
		}

		// Fallback to pattern match
		return MatchVersionPattern(normalizedMax, version)
	}

	cmp, ok := CompareSemVer(vClean, maxClean)
	if !ok {
		return false
	}

	if isStrictLess {
		return cmp < 0
	}
	return cmp <= 0
}
