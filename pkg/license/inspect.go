package license

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatInspect returns a standardized multi-line terminal inspection output
// of the claims metadata evaluated at the current system time.
func (c *Claims) FormatInspect() string {
	return c.FormatInspectAt(time.Now())
}

// FormatInspectAt returns a standardized multi-line terminal inspection output
// of the claims metadata evaluated at reference time t.
// Output includes Customer, Plan Tier, Product, Features, Limits, Scope,
// Version Bounds, Maintenance Cutoff, Validity Timeline, and Custom Metadata.
func (c *Claims) FormatInspectAt(t time.Time) string {
	if c == nil {
		return "No license claims to inspect\n"
	}

	var b strings.Builder
	headerDivider := strings.Repeat("=", 80)

	b.WriteString(headerDivider + "\n")
	b.WriteString("DIVMORA LICENSE CLAIMS\n")
	b.WriteString(headerDivider + "\n")

	// Overview
	fmt.Fprintf(&b, "%-24s %s\n", "Status:", c.StatusMessageAt(t))
	if c.Product != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Product:", c.Product)
	}
	if c.Plan != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Plan / Tier:", c.Plan)
	}
	if c.ID != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "License ID:", c.ID)
	}
	if c.KeyID != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Signing Key ID:", c.KeyID)
	}

	// Customer Section
	b.WriteString("\nCUSTOMER\n")
	custName := c.Customer.Name
	if custName == "" {
		custName = "(unspecified)"
	}
	fmt.Fprintf(&b, "  %-22s %s\n", "Name:", custName)
	if c.Customer.Email != "" {
		fmt.Fprintf(&b, "  %-22s %s\n", "Email:", c.Customer.Email)
	}
	if c.Customer.OrgID != "" {
		fmt.Fprintf(&b, "  %-22s %s\n", "Org ID:", c.Customer.OrgID)
	}

	// Validity Timeline
	b.WriteString("\nVALIDITY TIMELINE\n")
	if !c.IssuedAt.IsZero() {
		fmt.Fprintf(&b, "  %-22s %s\n", "Issued At:", c.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() {
		fmt.Fprintf(&b, "  %-22s %s\n", "Valid From:", c.NotBefore.UTC().Format(time.RFC3339))
	}
	if c.IsPerpetual() {
		fmt.Fprintf(&b, "  %-22s %s\n", "Expires At:", "Perpetual (Does not expire)")
	} else {
		fmt.Fprintf(&b, "  %-22s %s\n", "Expires At:", c.ExpiresAt.UTC().Format(time.RFC3339))
		if c.GracePeriodDays > 0 {
			cutoff := c.EffectiveExpiration().UTC().Format(time.RFC3339)
			fmt.Fprintf(&b, "  %-22s %d days (cutoff: %s)\n", "Grace Period:", c.GracePeriodDays, cutoff)
		}
	}

	// Version Bounds & Maintenance
	hasVersion := c.MaxVersion != "" || len(c.AllowedVersions) > 0 || !c.MaintenanceExpiresAt.IsZero()
	if hasVersion {
		b.WriteString("\nVERSION & MAINTENANCE\n")
		if c.MaxVersion != "" {
			fmt.Fprintf(&b, "  %-22s %s\n", "Max Version:", c.MaxVersion)
		}
		if len(c.AllowedVersions) > 0 {
			fmt.Fprintf(&b, "  %-22s %s\n", "Allowed Versions:", strings.Join(c.AllowedVersions, ", "))
		}
		if !c.MaintenanceExpiresAt.IsZero() {
			fmt.Fprintf(&b, "  %-22s %s\n", "Maintenance Cutoff:", c.MaintenanceExpiresAt.UTC().Format(time.RFC3339))
		}
	}

	// Entitlements & Resource Limits
	b.WriteString("\nENTITLEMENTS & QUOTAS\n")
	if len(c.Features) == 0 {
		fmt.Fprintf(&b, "  %-22s %s\n", "Features:", "(none)")
	} else {
		hasWildcard := false
		for _, f := range c.Features {
			trimmed := strings.TrimSpace(f)
			if trimmed == "*" || strings.EqualFold(trimmed, "all") {
				hasWildcard = true
				break
			}
		}
		if hasWildcard {
			fmt.Fprintf(&b, "  %-22s %s\n", "Features:", "* (All features entitled)")
		} else {
			sortedFeats := make([]string, len(c.Features))
			copy(sortedFeats, c.Features)
			sort.Strings(sortedFeats)
			fmt.Fprintf(&b, "  %-22s %s\n", "Features:", strings.Join(sortedFeats, ", "))
		}
	}

	if len(c.Limits) == 0 {
		fmt.Fprintf(&b, "  %-22s %s\n", "Limits:", "(unrestricted)")
	} else {
		b.WriteString("  Limits:\n")
		limitKeys := make([]string, 0, len(c.Limits))
		for k := range c.Limits {
			limitKeys = append(limitKeys, k)
		}
		sort.Strings(limitKeys)
		for _, k := range limitKeys {
			val := c.Limits[k]
			if val == -1 {
				fmt.Fprintf(&b, "    • %-20s %s\n", k+":", "Unlimited (-1)")
			} else {
				fmt.Fprintf(&b, "    • %-20s %d\n", k+":", val)
			}
		}
	}

	// Operational Scope
	hasScope := c.Scope != nil && (len(c.Scope.Environments) > 0 || len(c.Scope.Accounts) > 0 ||
		len(c.Scope.Regions) > 0 || len(c.Scope.Clusters) > 0 || len(c.Scope.Namespaces) > 0 ||
		len(c.Scope.Hosts) > 0 || len(c.Scope.Custom) > 0)
	hasFingerprint := c.Fingerprint != ""
	hasEnv := c.Environment != ""

	if hasScope || hasFingerprint || hasEnv {
		b.WriteString("\nOPERATIONAL SCOPE\n")
		if c.Environment != "" {
			fmt.Fprintf(&b, "  %-22s %s\n", "Environment:", c.Environment)
		}
		if hasFingerprint {
			fmt.Fprintf(&b, "  %-22s %s\n", "Node Fingerprint:", c.Fingerprint)
		}
		if c.Scope != nil {
			if len(c.Scope.Environments) > 0 {
				fmt.Fprintf(&b, "  %-22s %s\n", "Environments:", strings.Join(c.Scope.Environments, ", "))
			}
			if len(c.Scope.Accounts) > 0 {
				fmt.Fprintf(&b, "  %-22s %s\n", "Accounts:", strings.Join(c.Scope.Accounts, ", "))
			}
			if len(c.Scope.Regions) > 0 {
				fmt.Fprintf(&b, "  %-22s %s\n", "Regions:", strings.Join(c.Scope.Regions, ", "))
			}
			if len(c.Scope.Clusters) > 0 {
				fmt.Fprintf(&b, "  %-22s %s\n", "Clusters:", strings.Join(c.Scope.Clusters, ", "))
			}
			if len(c.Scope.Namespaces) > 0 {
				fmt.Fprintf(&b, "  %-22s %s\n", "Namespaces:", strings.Join(c.Scope.Namespaces, ", "))
			}
			if len(c.Scope.Hosts) > 0 {
				fmt.Fprintf(&b, "  %-22s %s\n", "Hosts:", strings.Join(c.Scope.Hosts, ", "))
			}
			if len(c.Scope.Custom) > 0 {
				b.WriteString("  Custom Dimensions:\n")
				customKeys := make([]string, 0, len(c.Scope.Custom))
				for k := range c.Scope.Custom {
					customKeys = append(customKeys, k)
				}
				sort.Strings(customKeys)
				for _, k := range customKeys {
					vals := c.Scope.Custom[k]
					fmt.Fprintf(&b, "    • %-20s %s\n", k+":", strings.Join(vals, ", "))
				}
			}
		}
	}

	// Custom Metadata
	if len(c.Metadata) > 0 {
		b.WriteString("\nMETADATA\n")
		metaKeys := make([]string, 0, len(c.Metadata))
		for k := range c.Metadata {
			metaKeys = append(metaKeys, k)
		}
		sort.Strings(metaKeys)
		for _, k := range metaKeys {
			fmt.Fprintf(&b, "  • %-22s %s\n", k+":", c.Metadata[k])
		}
	}

	b.WriteString(headerDivider + "\n")
	return b.String()
}

// FormatInspect returns a standardized multi-line terminal inspection output
// of the verification result, including cryptographic key validation, clock attestation,
// and formatted claims metadata.
func (r *VerificationResult) FormatInspect() string {
	if r == nil {
		return "No verification result to inspect\n"
	}

	var b strings.Builder
	headerDivider := strings.Repeat("=", 80)
	divider := strings.Repeat("-", 80)

	b.WriteString(headerDivider + "\n")
	b.WriteString("DIVMORA LICENSE VERIFICATION RESULT\n")
	b.WriteString(headerDivider + "\n")
	fmt.Fprintf(&b, "%-24s %s\n", "Status:", r.StatusMessage())

	if r.VerifiedByKeyID != "" {
		fmt.Fprintf(&b, "%-24s %s (Status: %s)\n", "Verified By Key:", r.VerifiedByKeyID, r.VerifiedByKeyStatus)
	}
	if r.BSLConverted {
		eff := r.EffectiveLicense
		if eff == "" {
			eff = "Apache-2.0"
		}
		if !r.ChangeDate.IsZero() {
			fmt.Fprintf(&b, "%-24s %s (Converted on %s)\n", "Governing License:", eff, r.ChangeDate.Format("2006-01-02"))
		} else {
			fmt.Fprintf(&b, "%-24s %s\n", "Governing License:", eff)
		}
	}
	if r.ServerTimeAttested {
		fmt.Fprintf(&b, "%-24s %s (Skew: %s)\n", "Server Time:", r.ServerTime.Format(time.RFC3339), r.ClockSkew)
	}
	if r.ClockTampered {
		b.WriteString("⚠️  WARNING: Clock tampering or excessive drift was detected!\n")
	}
	if r.Provenance != nil && r.Provenance.Attested {
		provClaims := r.Provenance.Claims
		if provClaims != nil {
			fmt.Fprintf(&b, "%-24s Certified Release (%s %s)\n", "Release Attestation:", provClaims.Product, provClaims.Version)
			if r.Provenance.VerifiedByKeyID != "" {
				fmt.Fprintf(&b, "%-24s %s (Status: %s)\n", "Attestation Key:", r.Provenance.VerifiedByKeyID, r.Provenance.VerifiedKeyStatus)
			}
			if provClaims.GitCommit != "" {
				fmt.Fprintf(&b, "%-24s %s\n", "Attested Git Commit:", provClaims.GitCommit)
			}
			if provClaims.BinaryDigest != "" {
				digestStatus := "Verified"
				if !r.Provenance.DigestMatched {
					digestStatus = "Not checked"
				}
				fmt.Fprintf(&b, "%-24s %s (%s)\n", "Binary Digest:", provClaims.BinaryDigest, digestStatus)
			}
		}
	}

	if r.Claims != nil {
		b.WriteString(divider + "\n")
		evalTime := r.EvaluationTime
		if evalTime.IsZero() {
			evalTime = time.Now()
		}
		b.WriteString(r.Claims.FormatInspectAt(evalTime))
	} else {
		b.WriteString(headerDivider + "\n")
	}

	return b.String()
}
