package license

import (
	"time"
)

const (
	// DefaultBSLChangeYears is the default period (3 years) before BSL 1.1 converts to open source.
	DefaultBSLChangeYears = 3

	// DefaultBSLChangeLicense is the target open-source license upon Change Date arrival.
	DefaultBSLChangeLicense = "Apache-2.0"

	// DefaultBSLLicense is the source-available license identifier prior to Change Date.
	DefaultBSLLicense = "BSL-1.1"
)

// BSLPolicy defines the Business Source License 1.1 parameters and autonomous open-source conversion rules.
type BSLPolicy struct {
	// ReleaseDate is the official compilation or release timestamp of this software version (required).
	ReleaseDate time.Time

	// ChangePeriodYears defines the duration in years before conversion (default: 3 years).
	ChangePeriodYears int

	// ExplicitChangeDate optionally overrides ReleaseDate + ChangePeriodYears with an explicit cutoff timestamp.
	ExplicitChangeDate time.Time

	// ChangeLicense is the target open-source license after conversion (default: "Apache-2.0").
	ChangeLicense string
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
