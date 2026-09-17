package license

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/divmora/license-go/internal/helpers"
)

const (
	// DefaultBSLChangeYears is the default period (3 years) before BSL 1.1 converts to open source.
	DefaultBSLChangeYears = 3

	// DefaultBSLChangeLicense is the target open-source license upon Change Date arrival.
	DefaultBSLChangeLicense = "Apache-2.0"

	// DefaultBSLLicense is the source-available license identifier prior to Change Date.
	DefaultBSLLicense = "BSL-1.1"
)

// BSLGrantType classifies the licensing entitlement status under BSL 1.1.
type BSLGrantType string

const (
	// BSLGrantTypeConverted indicates that the software has passed its Change Date and converted to open source.
	BSLGrantTypeConverted BSLGrantType = "CONVERTED_OPEN_SOURCE"

	// BSLGrantTypeAdditionalUseGrant indicates that usage is authorized under a BSL 1.1 Additional Use Grant.
	BSLGrantTypeAdditionalUseGrant BSLGrantType = "ADDITIONAL_USE_GRANT"

	// BSLGrantTypeRequiresCommercial indicates that usage exceeds or is excluded from all Additional Use Grants.
	BSLGrantTypeRequiresCommercial BSLGrantType = "COMMERCIAL_LICENSE_REQUIRED"
)

// BSLUsageRequest specifies the operational context, deployment environment, and consumption metrics to evaluate against BSL 1.1 terms.
type BSLUsageRequest struct {
	// Environment is the deployment environment name (e.g. "production", "staging", "development").
	Environment string `json:"environment,omitempty"`

	// Usage maps resource metrics to active consumption counts (e.g. "max_nodes": 6, "max_runners": 15).
	Usage map[string]int64 `json:"usage,omitempty"`

	// Features lists feature flags requested or enabled by the application.
	Features []string `json:"features,omitempty"`

	// Time is the reference evaluation timestamp. If zero, current time is used.
	Time time.Time `json:"time,omitempty"`

	// DryRun indicates execution in non-destructive simulation or dry-run mode (e.g. CLI --dry-run).
	DryRun bool `json:"dry_run,omitempty"`

	// Simulation indicates execution in testing or simulation mode.
	Simulation bool `json:"simulation,omitempty"`

	// Metadata holds optional arbitrary operational context.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsDryRun reports whether the request represents a non-destructive dry-run or simulation mode,
// either via the DryRun/Simulation boolean fields or via metadata (e.g. "dry_run": "true", "simulation": "true").
func (req BSLUsageRequest) IsDryRun() bool {
	if req.DryRun || req.Simulation {
		return true
	}
	if req.Metadata != nil {
		for _, k := range []string{"dry_run", "simulation", "dry-run", "dryrun"} {
			if strings.EqualFold(req.Metadata[k], "true") || strings.EqualFold(req.Metadata[k], "1") {
				return true
			}
		}
	}
	return false
}

// BSLGrantEvaluation records the detailed evaluation outcome for a single BSLAdditionalUseGrant.
type BSLGrantEvaluation struct {
	GrantName          string           `json:"grant_name"`
	Matched            bool             `json:"matched"`
	Reason             string           `json:"reason"`
	ExceededLimits     map[string]int64 `json:"exceeded_limits,omitempty"`
	DisallowedFeatures []string         `json:"disallowed_features,omitempty"`
}

// BSLAdditionalUseGrant defines permitted non-commercial or free-tier usage rights under BSL 1.1 prior to Change Date.
type BSLAdditionalUseGrant struct {
	// Name is a descriptive identifier for this grant (e.g. "Non-Production Exemption", "Community Free Tier").
	Name string `json:"name"`

	// Description provides human-readable documentation of the grant terms.
	Description string `json:"description,omitempty"`

	// AllowedEnvironments lists environments permitted by this grant (case-insensitive).
	// If empty or contains "*", all non-excluded environments are permitted.
	AllowedEnvironments []string `json:"allowed_environments,omitempty"`

	// ExcludedEnvironments lists environments explicitly barred from this grant (e.g. ["production", "prod"]).
	ExcludedEnvironments []string `json:"excluded_environments,omitempty"`

	// Limits defines maximum permitted capacity bounds for this grant (e.g. "max_nodes": 5).
	// A value of -1 denotes unlimited capacity for that metric.
	Limits map[string]int64 `json:"limits,omitempty"`

	// AllowedFeatures lists permitted feature flags under this grant.
	// If empty or contains "*", all non-excluded features are permitted.
	AllowedFeatures []string `json:"allowed_features,omitempty"`

	// ExcludedFeatures lists commercial-only features that disqualify this grant.
	ExcludedFeatures []string `json:"excluded_features,omitempty"`

	// MatchFunc allows custom programmatic evaluation logic.
	MatchFunc func(req BSLUsageRequest) (allowed bool, reason string) `json:"-"`
}

// DefaultNonProductionEnvironments is the standard list of non-production environments exempt under NewNonProductionGrant.
var DefaultNonProductionEnvironments = []string{
	"development", "dev",
	"staging", "stage",
	"test", "testing",
	"demo", "benchmark",
	"qa", "sandbox",
	"local", "ci", "cd",
}

// NewNonProductionGrant constructs an Additional Use Grant permitting unlimited usage in non-production environments.
func NewNonProductionGrant(name string, exemptEnvs ...string) BSLAdditionalUseGrant {
	if name == "" {
		name = "Non-Production Exemption"
	}
	envs := exemptEnvs
	if len(envs) == 0 {
		envs = make([]string, len(DefaultNonProductionEnvironments))
		copy(envs, DefaultNonProductionEnvironments)
	}
	return BSLAdditionalUseGrant{
		Name:                 name,
		Description:          "Permits non-production, development, staging, testing, and benchmarking deployments free of charge without a commercial license.",
		AllowedEnvironments:  envs,
		ExcludedEnvironments: []string{"production", "prod"},
	}
}

// NewFreeTierGrant constructs an Additional Use Grant permitting free community usage up to designated quota thresholds.
func NewFreeTierGrant(name string, limits map[string]int64, excludedFeatures ...string) BSLAdditionalUseGrant {
	if name == "" {
		name = "Community Free Tier"
	}
	limitsCopy := make(map[string]int64, len(limits))
	for k, v := range limits {
		limitsCopy[k] = v
	}
	return BSLAdditionalUseGrant{
		Name:             name,
		Description:      "Permits free community production and non-production usage up to specified quota bounds without requiring a commercial license.",
		Limits:           limitsCopy,
		ExcludedFeatures: excludedFeatures,
	}
}

// Evaluate tests whether the given request satisfies this grant.
func (g *BSLAdditionalUseGrant) Evaluate(req BSLUsageRequest) BSLGrantEvaluation {
	grantName := g.Name
	if grantName == "" {
		grantName = "Unnamed Grant"
	}

	reqEnv := strings.TrimSpace(req.Environment)
	isDryRun := req.IsDryRun()

	// 1. Custom MatchFunc priority evaluation
	// Evaluated before environment checks to allow custom predicates or simulation metadata
	// to bypass environment blacklists (e.g. non-destructive dry-run against production fleets).
	matchFuncEvaluated := false
	matchFuncAllowed := false
	matchFuncReason := ""
	if g.MatchFunc != nil {
		matchFuncEvaluated = true
		matchFuncAllowed, matchFuncReason = g.MatchFunc(req)
		if !matchFuncAllowed && matchFuncReason != "" {
			return BSLGrantEvaluation{
				GrantName: grantName,
				Matched:   false,
				Reason:    matchFuncReason,
			}
		}
	}

	// 2. Environment exclusions (bypassed if request is dry-run/simulation or explicitly authorized by MatchFunc)
	if !isDryRun && !matchFuncAllowed && reqEnv != "" && len(g.ExcludedEnvironments) > 0 {
		for _, exc := range g.ExcludedEnvironments {
			if strings.EqualFold(strings.TrimSpace(exc), reqEnv) {
				return BSLGrantEvaluation{
					GrantName: grantName,
					Matched:   false,
					Reason:    fmt.Sprintf("environment %q is explicitly excluded from grant %q", reqEnv, grantName),
				}
			}
		}
	}

	// 3. Allowed environments check (bypassed if request is dry-run/simulation or explicitly authorized by MatchFunc)
	if !isDryRun && !matchFuncAllowed && len(g.AllowedEnvironments) > 0 && !helpers.ContainsCaseInsensitive(g.AllowedEnvironments, "*") {
		if reqEnv == "" {
			return BSLGrantEvaluation{
				GrantName: grantName,
				Matched:   false,
				Reason:    fmt.Sprintf("deployment environment is unspecified, but grant %q requires one of %v", grantName, g.AllowedEnvironments),
			}
		}
		if !helpers.ContainsCaseInsensitive(g.AllowedEnvironments, reqEnv) {
			return BSLGrantEvaluation{
				GrantName: grantName,
				Matched:   false,
				Reason:    fmt.Sprintf("environment %q is not authorized under grant %q (authorized: %v)", reqEnv, grantName, g.AllowedEnvironments),
			}
		}
	}

	// 4. Excluded features check (commercial-only features)
	if len(g.ExcludedFeatures) > 0 && len(req.Features) > 0 {
		var disallowed []string
		for _, feat := range req.Features {
			trimmedFeat := strings.TrimSpace(feat)
			if trimmedFeat == "" {
				continue
			}
			if helpers.ContainsCaseInsensitive(g.ExcludedFeatures, trimmedFeat) {
				disallowed = append(disallowed, trimmedFeat)
			}
		}
		if len(disallowed) > 0 {
			sort.Strings(disallowed)
			return BSLGrantEvaluation{
				GrantName:          grantName,
				Matched:            false,
				DisallowedFeatures: disallowed,
				Reason:             fmt.Sprintf("feature(s) %v are excluded from grant %q and require a commercial license", disallowed, grantName),
			}
		}
	}

	// 5. Allowed features check
	if len(g.AllowedFeatures) > 0 && !helpers.ContainsCaseInsensitive(g.AllowedFeatures, "*") && !helpers.ContainsCaseInsensitive(g.AllowedFeatures, "all") && len(req.Features) > 0 {
		var unentitled []string
		for _, feat := range req.Features {
			trimmedFeat := strings.TrimSpace(feat)
			if trimmedFeat == "" {
				continue
			}
			if !helpers.ContainsCaseInsensitive(g.AllowedFeatures, trimmedFeat) {
				unentitled = append(unentitled, trimmedFeat)
			}
		}
		if len(unentitled) > 0 {
			sort.Strings(unentitled)
			return BSLGrantEvaluation{
				GrantName:          grantName,
				Matched:            false,
				DisallowedFeatures: unentitled,
				Reason:             fmt.Sprintf("feature(s) %v are not entitled under grant %q (authorized: %v)", unentitled, grantName, g.AllowedFeatures),
			}
		}
	}

	// 6. Quota limits check
	if len(g.Limits) > 0 && len(req.Usage) > 0 {
		exceeded := make(map[string]int64)
		var limitReasons []string
		for metric, limit := range g.Limits {
			used, hasUsage := req.Usage[metric]
			if !hasUsage {
				continue
			}
			if limit >= 0 && used > limit {
				exceeded[metric] = used
				limitReasons = append(limitReasons, fmt.Sprintf("metric %q usage %d exceeds grant limit %d", metric, used, limit))
			}
		}
		if len(exceeded) > 0 {
			sort.Strings(limitReasons)
			return BSLGrantEvaluation{
				GrantName:      grantName,
				Matched:        false,
				ExceededLimits: exceeded,
				Reason:         strings.Join(limitReasons, "; "),
			}
		}
	}

	// 7. Final MatchFunc check if it returned false without an explicit reason
	if matchFuncEvaluated && !matchFuncAllowed {
		hasStandardCriteria := len(g.AllowedEnvironments) > 0 || len(g.Limits) > 0 || len(g.AllowedFeatures) > 0
		if !hasStandardCriteria || (len(g.AllowedEnvironments) > 0 && !helpers.ContainsCaseInsensitive(g.AllowedEnvironments, reqEnv)) {
			reason := matchFuncReason
			if reason == "" {
				reason = fmt.Sprintf("custom predicate for grant %q rejected the usage request", grantName)
			}
			return BSLGrantEvaluation{
				GrantName: grantName,
				Matched:   false,
				Reason:    reason,
			}
		}
	}

	reason := fmt.Sprintf("usage satisfies terms of grant %q", grantName)
	if matchFuncReason != "" {
		reason = matchFuncReason
	} else if isDryRun {
		reason = fmt.Sprintf("execution in non-destructive dry-run/simulation mode authorized under grant %q", grantName)
	}

	return BSLGrantEvaluation{
		GrantName: grantName,
		Matched:   true,
		Reason:    reason,
	}
}

// BSLEntitlementResult is the comprehensive evaluation result of a BSLUsageRequest against BSLPolicy terms.
type BSLEntitlementResult struct {
	// Authorized reports whether the requested usage is permitted without a commercial license.
	Authorized bool `json:"authorized"`

	// GrantType classifies the decision (CONVERTED_OPEN_SOURCE, ADDITIONAL_USE_GRANT, or COMMERCIAL_LICENSE_REQUIRED).
	GrantType BSLGrantType `json:"grant_type"`

	// EffectiveLicense is the governing license identifier ("BSL-1.1" or "Apache-2.0").
	EffectiveLicense string `json:"effective_license"`

	// MatchingGrant is the name of the grant that authorized this usage, if applicable.
	MatchingGrant string `json:"matching_grant,omitempty"`

	// Reason is a detailed, human-readable description of the evaluation outcome.
	Reason string `json:"reason"`

	// Claims contains synthetic Claims generated when authorized, enabling standard claims operations.
	Claims *Claims `json:"claims,omitempty"`

	// Evaluations contains individual evaluation results for each configured grant.
	Evaluations []BSLGrantEvaluation `json:"evaluations,omitempty"`

	// ChangeDate is the timestamp when the software converts to open source under BSL terms.
	ChangeDate time.Time `json:"change_date,omitempty"`

	// DaysUntilConversion indicates remaining days before open-source conversion.
	DaysUntilConversion int `json:"days_until_conversion,omitempty"`
}

// StatusMessage returns a concise human-readable summary of the entitlement decision.
func (r *BSLEntitlementResult) StatusMessage() string {
	if r == nil {
		return "No entitlement evaluation result"
	}
	if r.GrantType == BSLGrantTypeConverted {
		if !r.ChangeDate.IsZero() {
			return fmt.Sprintf("Open source license (BSL 1.1 converted to %s on %s)", r.EffectiveLicense, r.ChangeDate.Format("2006-01-02"))
		}
		return fmt.Sprintf("Open source license (BSL 1.1 converted to %s)", r.EffectiveLicense)
	}
	if r.Authorized {
		if r.MatchingGrant != "" {
			return fmt.Sprintf("Authorized under BSL 1.1 Additional Use Grant (%s)", r.MatchingGrant)
		}
		return "Authorized under BSL 1.1 Additional Use Grant"
	}
	if r.DaysUntilConversion > 0 {
		return fmt.Sprintf("Commercial license required (BSL 1.1 converts to %s in %d days)", r.EffectiveLicense, r.DaysUntilConversion)
	}
	return "Commercial license required (BSL 1.1)"
}

// BSLPolicy defines the Business Source License 1.1 parameters, autonomous open-source conversion rules,
// and vendor-specific Additional Use Grants.
type BSLPolicy struct {
	// ReleaseDate is the official compilation or release timestamp of this software version (required).
	ReleaseDate time.Time

	// ChangePeriodYears defines the duration in years before conversion (default: 3 years).
	ChangePeriodYears int

	// ExplicitChangeDate optionally overrides ReleaseDate + ChangePeriodYears with an explicit cutoff timestamp.
	ExplicitChangeDate time.Time

	// ChangeLicense is the target open-source license after conversion (default: "Apache-2.0").
	ChangeLicense string

	// AdditionalUseGrants defines vendor-specific use exemptions and free tiers permitted prior to Change Date.
	AdditionalUseGrants []BSLAdditionalUseGrant

	// Product is the product name to populate in synthetic claims (default: "divmora-product").
	Product string
}

// ChangeDate returns the absolute timestamp when the BSL 1.1 license converts to open source.
func (b *BSLPolicy) ChangeDate() time.Time {
	if !b.ExplicitChangeDate.IsZero() {
		return b.ExplicitChangeDate
	}
	if b.ReleaseDate.IsZero() {
		return time.Time{}
	}
	years := b.ChangePeriodYears
	if years <= 0 {
		years = DefaultBSLChangeYears
	}
	return b.ReleaseDate.AddDate(years, 0, 0)
}

// IsConverted reports whether the software has converted to its open-source ChangeLicense at the given time.
func (b *BSLPolicy) IsConverted(at time.Time) bool {
	changeDate := b.ChangeDate()
	if changeDate.IsZero() {
		return false
	}
	return !at.Before(changeDate)
}

// EffectiveLicense returns ChangeLicense (e.g. "Apache-2.0") if converted, otherwise "BSL-1.1".
func (b *BSLPolicy) EffectiveLicense(at time.Time) string {
	if b.IsConverted(at) {
		if b.ChangeLicense != "" {
			return b.ChangeLicense
		}
		return DefaultBSLChangeLicense
	}
	return DefaultBSLLicense
}

// DaysUntilConversion returns the remaining full days until the software converts to open source.
// Returns 0 if already converted or if no ReleaseDate is configured.
func (b *BSLPolicy) DaysUntilConversion(at time.Time) int {
	changeDate := b.ChangeDate()
	if changeDate.IsZero() || !at.Before(changeDate) {
		return 0
	}
	diff := changeDate.Sub(at)
	return int(diff.Hours() / 24)
}

// AddGrant appends an Additional Use Grant to this policy.
func (b *BSLPolicy) AddGrant(grant BSLAdditionalUseGrant) {
	b.AdditionalUseGrants = append(b.AdditionalUseGrants, grant)
}

// WithGrants returns a copy of BSLPolicy with the specified grants added.
func (b BSLPolicy) WithGrants(grants ...BSLAdditionalUseGrant) BSLPolicy {
	b.AdditionalUseGrants = append(b.AdditionalUseGrants, grants...)
	return b
}

// EvaluateEntitlement evaluates whether the requested usage is authorized under BSL 1.1 terms,
// either via autonomous open-source conversion or via an Additional Use Grant.
func (b *BSLPolicy) EvaluateEntitlement(req BSLUsageRequest) *BSLEntitlementResult {
	evalTime := req.Time
	if evalTime.IsZero() {
		evalTime = time.Now()
	}
	return b.EvaluateEntitlementAt(req, evalTime)
}

// EvaluateEntitlementAt evaluates whether the requested usage is authorized at the specified reference timestamp.
func (b *BSLPolicy) EvaluateEntitlementAt(req BSLUsageRequest, at time.Time) *BSLEntitlementResult {
	changeDate := b.ChangeDate()
	daysUntil := b.DaysUntilConversion(at)
	targetLic := b.ChangeLicense
	if targetLic == "" {
		targetLic = DefaultBSLChangeLicense
	}
	product := b.Product
	if product == "" {
		product = "divmora-product"
	}

	// 1. Check if BSL 1.1 Change Date has arrived -> Autonomous open-source conversion
	if b.IsConverted(at) {
		var reason string
		if !changeDate.IsZero() {
			reason = fmt.Sprintf("Open-source license: BSL 1.1 converted to %s on %s", targetLic, changeDate.Format("2006-01-02"))
		} else {
			reason = fmt.Sprintf("Open-source license: BSL 1.1 converted to %s", targetLic)
		}
		claims := &Claims{
			Product:  product,
			Plan:     "open-source",
			Customer: Customer{Name: "Open Source Community"},
			Features: []string{"*"},
			Limits:   map[string]int64{},
		}
		return &BSLEntitlementResult{
			Authorized:          true,
			GrantType:           BSLGrantTypeConverted,
			EffectiveLicense:    targetLic,
			Reason:              reason,
			Claims:              claims,
			ChangeDate:          changeDate,
			DaysUntilConversion: 0,
		}
	}

	// 2. If not converted and no grants are configured -> Commercial license required
	if len(b.AdditionalUseGrants) == 0 {
		var reason string
		if !changeDate.IsZero() {
			reason = fmt.Sprintf("Commercial license required: software is licensed under BSL 1.1 (converts to %s in %d days on %s) with no Additional Use Grants configured", targetLic, daysUntil, changeDate.Format("2006-01-02"))
		} else {
			reason = "Commercial license required: software is licensed under BSL 1.1 with no Additional Use Grants configured"
		}
		return &BSLEntitlementResult{
			Authorized:          false,
			GrantType:           BSLGrantTypeRequiresCommercial,
			EffectiveLicense:    DefaultBSLLicense,
			Reason:              reason,
			ChangeDate:          changeDate,
			DaysUntilConversion: daysUntil,
		}
	}

	// 3. Evaluate each Additional Use Grant
	var evals []BSLGrantEvaluation
	reqCopy := req
	reqCopy.Time = at

	for _, grant := range b.AdditionalUseGrants {
		eval := grant.Evaluate(reqCopy)
		evals = append(evals, eval)
		if eval.Matched {
			// Authorized under this grant!
			grantLimits := make(map[string]int64, len(grant.Limits))
			for k, v := range grant.Limits {
				grantLimits[k] = v
			}
			grantFeatures := grant.AllowedFeatures
			if len(grantFeatures) == 0 {
				grantFeatures = []string{"*"}
			}
			claims := &Claims{
				Product:  product,
				Plan:     "bsl-additional-use-grant",
				Customer: Customer{Name: fmt.Sprintf("BSL Additional Use Grant (%s)", grant.Name)},
				Features: grantFeatures,
				Limits:   grantLimits,
				Scope: &Scope{
					Environments: grant.AllowedEnvironments,
				},
			}
			return &BSLEntitlementResult{
				Authorized:          true,
				GrantType:           BSLGrantTypeAdditionalUseGrant,
				EffectiveLicense:    DefaultBSLLicense,
				MatchingGrant:       grant.Name,
				Reason:              fmt.Sprintf("Usage authorized under Additional Use Grant '%s': %s", grant.Name, eval.Reason),
				Claims:              claims,
				Evaluations:         evals,
				ChangeDate:          changeDate,
				DaysUntilConversion: daysUntil,
			}
		}
	}

	// 4. None of the grants matched
	var failReasons []string
	for _, ev := range evals {
		failReasons = append(failReasons, fmt.Sprintf("%s (%s)", ev.GrantName, ev.Reason))
	}
	reason := fmt.Sprintf("Commercial license required: usage does not satisfy any BSL 1.1 Additional Use Grants: %s", strings.Join(failReasons, "; "))

	return &BSLEntitlementResult{
		Authorized:          false,
		GrantType:           BSLGrantTypeRequiresCommercial,
		EffectiveLicense:    DefaultBSLLicense,
		Reason:              reason,
		Evaluations:         evals,
		ChangeDate:          changeDate,
		DaysUntilConversion: daysUntil,
	}
}
