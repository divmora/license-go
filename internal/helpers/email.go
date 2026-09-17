package helpers

import (
	"net/mail"
	"strings"
)

// IsValidEmail validates an email address string against standard email format requirements
// (RFC 5322 compliance and domain dot verification).
func IsValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	// ParseAddress allows "Name <email@example.com>", ensure entire string was parsed as address without display name if raw
	if addr.Address != email && !strings.Contains(email, "<") {
		return false
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	// Domain must contain at least one dot and non-empty segments
	domain := parts[1]
	if !strings.Contains(domain, ".") {
		return false
	}
	domainParts := strings.Split(domain, ".")
	for _, p := range domainParts {
		if p == "" {
			return false
		}
	}
	return true
}
