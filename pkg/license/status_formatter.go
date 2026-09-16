package license

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	defaultBannerWidth = 80
	defaultBannerTitle = "DIVMORA SOFTWARE LICENSE STATUS"
)

// StatusFormatterOption configures the formatting of standardized CLI license status banners and tables.
type StatusFormatterOption func(*statusFormatterConfig)

type statusFormatterConfig struct {
	evalTime          time.Time
	usage             map[string]int64
	usageFunc         func(string) (int64, bool)
	bannerTitle       string
	includeQuotas     bool
	includeFeatures   bool
	includeScopes     bool
	includeProvenance bool
	compact           bool
	width             int
}

func defaultFormatterConfig() *statusFormatterConfig {
	return &statusFormatterConfig{
		evalTime:          time.Now().UTC(),
		bannerTitle:       defaultBannerTitle,
		includeQuotas:     true,
		includeFeatures:   true,
		includeScopes:     true,
		includeProvenance: true,
		compact:           false,
		width:             defaultBannerWidth,
	}
}

// WithStatusTime sets the reference time used to evaluate countdowns and remaining days.
func WithStatusTime(t time.Time) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		if !t.IsZero() {
			c.evalTime = t.UTC()
		}
	}
}

// WithStatusUsage sets a map of current resource usage counts to overlay against licensed quotas.
func WithStatusUsage(usage map[string]int64) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.usage = usage
	}
}

// WithStatusUsageFunc sets a callback to query live resource counts for each quota dimension.
func WithStatusUsageFunc(fn func(string) (int64, bool)) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.usageFunc = fn
	}
}

// WithStatusBannerTitle sets a custom header title for the status card.
func WithStatusBannerTitle(title string) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		if strings.TrimSpace(title) != "" {
			c.bannerTitle = strings.TrimSpace(title)
		}
	}
}

// WithStatusIncludeQuotas toggles inclusion of the resource quota & capacity table (default: true).
func WithStatusIncludeQuotas(include bool) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.includeQuotas = include
	}
}

// WithStatusIncludeFeatures toggles inclusion of the entitled features list (default: true).
func WithStatusIncludeFeatures(include bool) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.includeFeatures = include
	}
}

// WithStatusIncludeScopes toggles inclusion of operational infrastructure scope constraints (default: true).
func WithStatusIncludeScopes(include bool) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.includeScopes = include
	}
}

// WithStatusIncludeProvenance toggles inclusion of release attestation and provenance status (default: true).
func WithStatusIncludeProvenance(include bool) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.includeProvenance = include
	}
}

// WithStatusCompact enables a compact layout omitting verbose feature and scope lists.
func WithStatusCompact(compact bool) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		c.compact = compact
	}
}

// WithStatusWidth configures the horizontal banner width in columns (default: 80, minimum: 60).
func WithStatusWidth(width int) StatusFormatterOption {
	return func(c *statusFormatterConfig) {
		if width >= 60 {
			c.width = width
		}
	}
}

// FormatStatus returns a standardized terminal status card and capacity table for this verification result.
func (r *VerificationResult) FormatStatus(opts ...StatusFormatterOption) string {
	return formatResultStatus(r, opts...)
}

// FormatStatusBanner is a convenience alias for FormatStatus.
func (r *VerificationResult) FormatStatusBanner(opts ...StatusFormatterOption) string {
	return r.FormatStatus(opts...)
}

// FormatStatus returns a standardized terminal status card and capacity table for these claims.
func (c *Claims) FormatStatus(opts ...StatusFormatterOption) string {
	return formatClaimsStatus(c, opts...)
}

// FormatStatusBanner is a convenience alias for FormatStatus.
func (c *Claims) FormatStatusBanner(opts ...StatusFormatterOption) string {
	return c.FormatStatus(opts...)
}

// FormatStatus formats a VerificationResult into a standardized terminal status card.
func FormatStatus(res *VerificationResult, opts ...StatusFormatterOption) string {
	return formatResultStatus(res, opts...)
}

// FormatClaimsStatus formats a Claims object into a standardized terminal status card.
func FormatClaimsStatus(claims *Claims, opts ...StatusFormatterOption) string {
	return formatClaimsStatus(claims, opts...)
}

func formatResultStatus(r *VerificationResult, opts ...StatusFormatterOption) string {
	if r == nil {
		return "No verification result available\n"
	}

	cfg := defaultFormatterConfig()
	if !r.EvaluationTime.IsZero() {
		cfg.evalTime = r.EvaluationTime.UTC()
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var b strings.Builder
	headerDivider := strings.Repeat("=", cfg.width)

	b.WriteString(headerDivider + "\n")
	b.WriteString(cfg.bannerTitle + "\n")
	b.WriteString(headerDivider + "\n")

	// 1. Status Indicator
	statusLabel := formatResultStatusBadge(r, cfg.evalTime)
	fmt.Fprintf(&b, "%-24s %s\n", "Status:", statusLabel)

	// 2. Product and Tier
	product := "(unspecified)"
	if r.Claims != nil && r.Claims.Product != "" {
		product = r.Claims.Product
	}
	fmt.Fprintf(&b, "%-24s %s\n", "Product:", product)

	plan := "standard"
	if r.BSLConverted {
		plan = "open-source community"
	} else if r.Claims != nil && r.Claims.Plan != "" {
		plan = r.Claims.Plan
	}
	fmt.Fprintf(&b, "%-24s %s\n", "Subscription Tier:", strings.ToUpper(plan))

	// 3. Customer
	if r.Claims != nil {
		cust := r.Claims.Customer.Name
		if cust == "" {
			cust = "(unspecified)"
		}
		if r.Claims.Customer.OrgID != "" {
			cust = fmt.Sprintf("%s (Org: %s)", cust, r.Claims.Customer.OrgID)
		} else if r.Claims.Customer.Email != "" {
			cust = fmt.Sprintf("%s <%s>", cust, r.Claims.Customer.Email)
		}
		fmt.Fprintf(&b, "%-24s %s\n", "Licensed To:", cust)
	}

	// 4. Validity Window & Expiration
	if r.BSLConverted {
		eff := r.EffectiveLicense
		if eff == "" {
			eff = DefaultBSLChangeLicense
		}
		if !r.ChangeDate.IsZero() {
			fmt.Fprintf(&b, "%-24s %s (Change Date reached %s)\n",
				"Governing License:", eff, r.ChangeDate.Format("2006-01-02"))
		} else {
			fmt.Fprintf(&b, "%-24s %s (BSL 1.1 Converted)\n", "Governing License:", eff)
		}
	} else if r.Claims != nil {
		fmt.Fprintf(&b, "%-24s %s\n", "Validity Window:", r.Claims.StatusMessageAt(cfg.evalTime))
		if r.InGracePeriod || r.Status == StatusGracePeriod {
			cutoff := r.EffectiveExpiry
			if cutoff.IsZero() {
				cutoff = r.Claims.EffectiveExpiration()
			}
			fmt.Fprintf(&b, "%-24s Operating under %d-day grace period (cutoff: %s)\n",
				"Grace Period:", r.Claims.GracePeriodDays, cutoff.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
	}

	// 5. BSL 1.1 Countdown (if pending conversion)
	if !r.BSLConverted && !r.ChangeDate.IsZero() {
		if r.ChangeDate.After(cfg.evalTime) {
			diff := r.ChangeDate.Sub(cfg.evalTime)
			days := int(diff.Hours() / 24)
			targetLic := DefaultBSLChangeLicense
			if r.EffectiveLicense != "" && r.EffectiveLicense != DefaultBSLLicense {
				targetLic = r.EffectiveLicense
			}
			fmt.Fprintf(&b, "%-24s Converts to %s in %d days (%s)\n",
				"BSL 1.1 Transition:", targetLic, days, r.ChangeDate.Format("2006-01-02"))
		}
	}

	// 6. Release Provenance Attestation
	if cfg.includeProvenance && r.Provenance != nil && r.Provenance.Attested {
		prov := r.Provenance
		if prov.Claims != nil {
			digestStatus := "Verified"
			if !prov.DigestMatched {
				digestStatus = "Attested"
			}
			fmt.Fprintf(&b, "%-24s Certified Release %s (Checksum: %s)\n",
				"Release Provenance:", prov.Claims.Version, digestStatus)
			if prov.Claims.GitCommit != "" {
				fmt.Fprintf(&b, "%-24s %s\n", "Attested Git Commit:", prov.Claims.GitCommit)
			}
		}
	}

	// 7. Cryptographic Key Verification
	if r.VerifiedByKeyID != "" {
		fmt.Fprintf(&b, "%-24s %s (Key Status: %s)\n", "Verified By Key:", r.VerifiedByKeyID, r.VerifiedByKeyStatus)
	}
	if r.ServerTimeAttested {
		fmt.Fprintf(&b, "%-24s %s (Clock Skew: %s)\n", "Authoritative Time:",
			r.ServerTime.Format(time.RFC3339), r.ClockSkew)
	}

	// 8. Quotas and Capacity Table
	if cfg.includeQuotas && r.Claims != nil && len(r.Claims.Limits) > 0 {
		b.WriteString("\n")
		formatQuotaTable(&b, r.Claims.Limits, cfg)
	}

	// 9. Entitled Features
	if !cfg.compact && cfg.includeFeatures && r.Claims != nil && len(r.Claims.Features) > 0 {
		b.WriteString("\n")
		formatFeatureList(&b, r.Claims.Features)
	}

	// 10. Operational Scopes
	if !cfg.compact && cfg.includeScopes && r.Claims != nil {
		formatScopeSection(&b, r.Claims)
	}

	b.WriteString(headerDivider + "\n")
	return b.String()
}

func formatClaimsStatus(c *Claims, opts ...StatusFormatterOption) string {
	if c == nil {
		return "No license claims available\n"
	}

	cfg := defaultFormatterConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	var b strings.Builder
	headerDivider := strings.Repeat("=", cfg.width)

	b.WriteString(headerDivider + "\n")
	b.WriteString(cfg.bannerTitle + "\n")
	b.WriteString(headerDivider + "\n")

	// Status line
	statusBadge := formatClaimsStatusBadge(c, cfg.evalTime)
	fmt.Fprintf(&b, "%-24s %s\n", "Status:", statusBadge)
	if c.Product != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Product:", c.Product)
	}
	if c.Plan != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Subscription Tier:", strings.ToUpper(c.Plan))
	}

	cust := c.Customer.Name
	if cust == "" {
		cust = "(unspecified)"
	}
	if c.Customer.OrgID != "" {
		cust = fmt.Sprintf("%s (Org: %s)", cust, c.Customer.OrgID)
	} else if c.Customer.Email != "" {
		cust = fmt.Sprintf("%s <%s>", cust, c.Customer.Email)
	}
	fmt.Fprintf(&b, "%-24s %s\n", "Licensed To:", cust)
	fmt.Fprintf(&b, "%-24s %s\n", "Validity Window:", c.StatusMessageAt(cfg.evalTime))

	if c.IsInGracePeriodAt(cfg.evalTime) {
		cutoff := c.EffectiveExpiration()
		fmt.Fprintf(&b, "%-24s Operating under %d-day grace period (cutoff: %s)\n",
			"Grace Period:", c.GracePeriodDays, cutoff.UTC().Format("2006-01-02 15:04:05 UTC"))
	}

	if c.KeyID != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Signing Key ID:", c.KeyID)
	}

	// Quotas table
	if cfg.includeQuotas && len(c.Limits) > 0 {
		b.WriteString("\n")
		formatQuotaTable(&b, c.Limits, cfg)
	}

	// Features
	if !cfg.compact && cfg.includeFeatures && len(c.Features) > 0 {
		b.WriteString("\n")
		formatFeatureList(&b, c.Features)
	}

	// Scopes
	if !cfg.compact && cfg.includeScopes {
		formatScopeSection(&b, c)
	}

	b.WriteString(headerDivider + "\n")
	return b.String()
}

func formatResultStatusBadge(r *VerificationResult, now time.Time) string {
	if r.BSLConverted {
		eff := r.EffectiveLicense
		if eff == "" {
			eff = DefaultBSLChangeLicense
		}
		return fmt.Sprintf("OPEN SOURCE [✓ Converted to %s]", eff)
	}
	if r.InGracePeriod || r.Status == StatusGracePeriod {
		remaining := r.GraceDaysRemaining
		if remaining <= 1 {
			return "GRACE PERIOD [⚠️ Operating under active grace buffer - expiring soon]"
		}
		return fmt.Sprintf("GRACE PERIOD [⚠️ Operating under active grace buffer - %d days remaining]", remaining)
	}
	switch r.Status {
	case StatusActive:
		return "ACTIVE [✓ Valid & Cryptographically Verified]"
	case StatusExpired:
		return "EXPIRED [❌ Commercial License Expired]"
	case StatusNotYetValid:
		return "PENDING [⏳ License Not Active Yet]"
	default:
		return string(r.Status)
	}
}

func formatClaimsStatusBadge(c *Claims, now time.Time) string {
	if c.IsInGracePeriodAt(now) {
		remaining := c.GraceDaysRemainingAt(now)
		return fmt.Sprintf("GRACE PERIOD [⚠️ Operating under active grace buffer - %d days remaining]", remaining)
	}
	st := c.StatusAt(now)
	switch st {
	case StatusActive:
		return "ACTIVE [✓ Valid Claims]"
	case StatusExpired:
		return "EXPIRED [❌ Commercial License Expired]"
	case StatusNotYetValid:
		return "PENDING [⏳ License Not Active Yet]"
	default:
		return string(st)
	}
}

func formatQuotaTable(b *strings.Builder, limits map[string]int64, cfg *statusFormatterConfig) {
	b.WriteString("RESOURCE QUOTAS & CAPACITY\n")

	limitKeys := make([]string, 0, len(limits))
	for k := range limits {
		limitKeys = append(limitKeys, k)
	}
	sort.Strings(limitKeys)

	hasUsage := len(cfg.usage) > 0 || cfg.usageFunc != nil

	if hasUsage {
		// Table with live utilization
		tableHeader := fmt.Sprintf("  %-24s %-12s %-14s %-16s %s", "RESOURCE", "USED", "LIMIT", "UTILIZATION", "HEADROOM")
		b.WriteString(tableHeader + "\n")
		b.WriteString("  " + strings.Repeat("-", cfg.width-2) + "\n")

		for _, k := range limitKeys {
			limitVal := limits[k]

			var usedVal int64
			var hasVal bool
			if cfg.usageFunc != nil {
				usedVal, hasVal = cfg.usageFunc(k)
			}
			if !hasVal && cfg.usage != nil {
				usedVal, hasVal = cfg.usage[k]
			}

			usedStr := "-"
			if hasVal {
				usedStr = fmt.Sprintf("%d", usedVal)
			}

			if limitVal == -1 {
				fmt.Fprintf(b, "  %-24s %-12s %-14s %-16s %s\n", k, usedStr, "Unlimited", "-", "Unlimited")
				continue
			}

			limitStr := fmt.Sprintf("%d", limitVal)
			utilStr := "-"
			headroomStr := "-"

			if hasVal {
				if limitVal > 0 {
					pct := (usedVal * 100) / limitVal
					if usedVal > limitVal {
						utilStr = fmt.Sprintf("%d%% [EXCEEDED]", pct)
						headroomStr = fmt.Sprintf("OVER QUOTA (+%d)", usedVal-limitVal)
					} else {
						utilStr = fmt.Sprintf("%d%%", pct)
						avail := limitVal - usedVal
						headroomStr = fmt.Sprintf("%d available", avail)
					}
				} else if limitVal == 0 {
					if usedVal > 0 {
						utilStr = "[EXCEEDED]"
						headroomStr = fmt.Sprintf("OVER QUOTA (+%d)", usedVal)
					} else {
						utilStr = "0%"
						headroomStr = "0 available"
					}
				}
			} else {
				headroomStr = fmt.Sprintf("%d total", limitVal)
			}

			fmt.Fprintf(b, "  %-24s %-12s %-14s %-16s %s\n", k, usedStr, limitStr, utilStr, headroomStr)
		}
	} else {
		// Static table
		tableHeader := fmt.Sprintf("  %-28s %-18s %s", "RESOURCE", "CAPACITY / LIMIT", "TYPE")
		b.WriteString(tableHeader + "\n")
		b.WriteString("  " + strings.Repeat("-", cfg.width-2) + "\n")

		for _, k := range limitKeys {
			val := limits[k]
			if val == -1 {
				fmt.Fprintf(b, "  %-28s %-18s %s\n", k, "Unlimited (-1)", "Unrestricted Quota")
			} else {
				fmt.Fprintf(b, "  %-28s %-18d %s\n", k, val, "Enforced Hard Quota")
			}
		}
	}
}

func formatFeatureList(b *strings.Builder, features []string) {
	fmt.Fprintf(b, "ENTITLED FEATURES (%d)\n", len(features))
	hasWildcard := false
	for _, f := range features {
		trimmed := strings.TrimSpace(f)
		if trimmed == "*" || strings.EqualFold(trimmed, "all") {
			hasWildcard = true
			break
		}
	}

	if hasWildcard {
		b.WriteString("  • * (All features entitled)\n")
		return
	}

	sortedFeats := make([]string, len(features))
	copy(sortedFeats, features)
	sort.Strings(sortedFeats)

	for _, f := range sortedFeats {
		fmt.Fprintf(b, "  • %s\n", f)
	}
}

func formatScopeSection(b *strings.Builder, c *Claims) {
	hasScope := c.Scope != nil && (len(c.Scope.Environments) > 0 || len(c.Scope.Accounts) > 0 ||
		len(c.Scope.Regions) > 0 || len(c.Scope.Clusters) > 0 || len(c.Scope.Namespaces) > 0 ||
		len(c.Scope.Hosts) > 0 || len(c.Scope.Custom) > 0)
	hasFingerprint := c.Fingerprint != ""
	hasEnv := c.Environment != ""

	if !hasScope && !hasFingerprint && !hasEnv {
		return
	}

	b.WriteString("\nOPERATIONAL SCOPE\n")
	if c.Environment != "" {
		fmt.Fprintf(b, "  %-22s %s\n", "Environment:", c.Environment)
	}
	if hasFingerprint {
		fmt.Fprintf(b, "  %-22s %s\n", "Node Fingerprint:", c.Fingerprint)
	}
	if c.Scope != nil {
		if len(c.Scope.Environments) > 0 {
			fmt.Fprintf(b, "  %-22s %s\n", "Environments:", strings.Join(c.Scope.Environments, ", "))
		}
		if len(c.Scope.Accounts) > 0 {
			fmt.Fprintf(b, "  %-22s %s\n", "Accounts:", strings.Join(c.Scope.Accounts, ", "))
		}
		if len(c.Scope.Regions) > 0 {
			fmt.Fprintf(b, "  %-22s %s\n", "Regions:", strings.Join(c.Scope.Regions, ", "))
		}
		if len(c.Scope.Clusters) > 0 {
			fmt.Fprintf(b, "  %-22s %s\n", "Clusters:", strings.Join(c.Scope.Clusters, ", "))
		}
		if len(c.Scope.Namespaces) > 0 {
			fmt.Fprintf(b, "  %-22s %s\n", "Namespaces:", strings.Join(c.Scope.Namespaces, ", "))
		}
		if len(c.Scope.Hosts) > 0 {
			fmt.Fprintf(b, "  %-22s %s\n", "Hosts:", strings.Join(c.Scope.Hosts, ", "))
		}
	}
}
