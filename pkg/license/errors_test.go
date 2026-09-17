package license

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStructuredErrors_ErrorFormattingAndIs(t *testing.T) {
	// 1. LimitExceededError
	limitErr := &LimitExceededError{LimitName: "runners", Current: 25, Allowed: 10}
	if !errors.Is(limitErr, ErrLimitExceeded) {
		t.Error("expected limitErr to match ErrLimitExceeded")
	}
	if !strings.Contains(limitErr.Error(), "limit 'runners' exceeded") {
		t.Errorf("unexpected LimitExceededError string: %s", limitErr.Error())
	}

	// 2. FeatureNotEntitledError
	featErr := &FeatureNotEntitledError{Feature: "ha"}
	if !errors.Is(featErr, ErrFeatureNotEntitled) {
		t.Error("expected featErr to match ErrFeatureNotEntitled")
	}
	if !strings.Contains(featErr.Error(), "feature 'ha' is not entitled") {
		t.Errorf("unexpected FeatureNotEntitledError string: %s", featErr.Error())
	}

	// 3. ScopeMismatchError
	scopeErr1 := &ScopeMismatchError{Dimension: "env", Allowed: []string{"prod"}, Target: "dev"}
	if !errors.Is(scopeErr1, ErrScopeMismatch) {
		t.Error("expected scopeErr1 to match ErrScopeMismatch")
	}
	if !strings.Contains(scopeErr1.Error(), "target \"dev\" is not authorized by [prod]") {
		t.Errorf("unexpected ScopeMismatchError string: %s", scopeErr1.Error())
	}

	scopeErrEmptyAllowed := &ScopeMismatchError{Dimension: "env", Allowed: nil}
	if !strings.Contains(scopeErrEmptyAllowed.Error(), "required by policy but not restricted") {
		t.Errorf("unexpected ScopeMismatchError string: %s", scopeErrEmptyAllowed.Error())
	}

	scopeErrEmptyTarget := &ScopeMismatchError{Dimension: "env", Allowed: []string{"prod"}, Target: ""}
	if !strings.Contains(scopeErrEmptyTarget.Error(), "no target was configured") {
		t.Errorf("unexpected ScopeMismatchError string: %s", scopeErrEmptyTarget.Error())
	}

	// 4. VersionNotEntitledError
	verErrMax := &VersionNotEntitledError{CurrentVersion: "2.1.0", MaxVersion: "2.0.0"}
	if !errors.Is(verErrMax, ErrVersionNotEntitled) {
		t.Error("expected verErrMax to match ErrVersionNotEntitled")
	}
	if !strings.Contains(verErrMax.Error(), "maximum authorized version is \"2.0.0\"") {
		t.Errorf("unexpected VersionNotEntitledError string: %s", verErrMax.Error())
	}

	verErrAllowed := &VersionNotEntitledError{CurrentVersion: "3.0.0", Allowed: []string{"1.*", "2.*"}}
	if !strings.Contains(verErrAllowed.Error(), "authorized versions: [1.* 2.*]") {
		t.Errorf("unexpected VersionNotEntitledError string: %s", verErrAllowed.Error())
	}

	verErrDefault := &VersionNotEntitledError{CurrentVersion: "3.0.0"}
	if !strings.Contains(verErrDefault.Error(), "is not entitled under this license") {
		t.Errorf("unexpected VersionNotEntitledError string: %s", verErrDefault.Error())
	}

	// 5. MaintenanceExpiredError
	maintErr := &MaintenanceExpiredError{BuildDate: "2026-06-01", MaintenanceExpiresAt: "2026-01-01"}
	if !errors.Is(maintErr, ErrMaintenanceExpired) {
		t.Error("expected maintErr to match ErrMaintenanceExpired")
	}
	if !strings.Contains(maintErr.Error(), "software build date 2026-06-01 exceeds maintenance cutoff date 2026-01-01") {
		t.Errorf("unexpected MaintenanceExpiredError string: %s", maintErr.Error())
	}

	// 6. ClockTamperingError
	now := time.Now().UTC()
	clockErrReason := &ClockTamperingError{
		LocalTime:      now,
		ServerTime:     now.Add(10 * time.Minute),
		Skew:           10 * time.Minute,
		MaxAllowedSkew: 1 * time.Minute,
		Reason:         "system time rolled backward",
	}
	if !errors.Is(clockErrReason, ErrClockTamperingDetected) {
		t.Error("expected clockErrReason to match ErrClockTamperingDetected")
	}
	if !strings.Contains(clockErrReason.Error(), "system time rolled backward") {
		t.Errorf("unexpected ClockTamperingError string: %s", clockErrReason.Error())
	}

	clockErrDefault := &ClockTamperingError{
		LocalTime:      now,
		ServerTime:     now.Add(10 * time.Minute),
		Skew:           10 * time.Minute,
		MaxAllowedSkew: 1 * time.Minute,
	}
	if !strings.Contains(clockErrDefault.Error(), "differs from authoritative server time") {
		t.Errorf("unexpected ClockTamperingError string: %s", clockErrDefault.Error())
	}

	// 7. ReleaseTamperingError
	relErrReason := &ReleaseTamperingError{
		Field:    "version",
		Expected: "v1.0.0",
		Actual:   "v2.0.0",
		Reason:   "version mismatch against attestation",
	}
	if !errors.Is(relErrReason, ErrReleaseTampered) {
		t.Error("expected relErrReason to match ErrReleaseTampered")
	}
	if !strings.Contains(relErrReason.Error(), "version mismatch against attestation") {
		t.Errorf("unexpected ReleaseTamperingError string: %s", relErrReason.Error())
	}

	relErrDefault := &ReleaseTamperingError{
		Field:    "sha256",
		Expected: "abc",
		Actual:   "def",
	}
	if !strings.Contains(relErrDefault.Error(), "release tampering detected on sha256") {
		t.Errorf("unexpected ReleaseTamperingError string: %s", relErrDefault.Error())
	}

	// 8. CommercialLicenseRequiredError
	commErrReason := &CommercialLicenseRequiredError{
		Reason: "usage limits exceeded free grant tier",
	}
	if !errors.Is(commErrReason, ErrCommercialLicenseRequired) || !errors.Is(commErrReason, ErrLicenseNotFound) {
		t.Error("expected commErrReason to match ErrCommercialLicenseRequired and ErrLicenseNotFound")
	}
	if !strings.Contains(commErrReason.Error(), "usage limits exceeded free grant tier") {
		t.Errorf("unexpected CommercialLicenseRequiredError string: %s", commErrReason.Error())
	}

	commErrEnv := &CommercialLicenseRequiredError{
		Environment: "production",
	}
	if !strings.Contains(commErrEnv.Error(), "deployment in \"production\" is not authorized") {
		t.Errorf("unexpected CommercialLicenseRequiredError string: %s", commErrEnv.Error())
	}

	commErrDefault := &CommercialLicenseRequiredError{}
	if !strings.Contains(commErrDefault.Error(), "commercial license required; usage exceeds") {
		t.Errorf("unexpected CommercialLicenseRequiredError string: %s", commErrDefault.Error())
	}
}
