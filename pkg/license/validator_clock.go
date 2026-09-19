package license

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ParseServerTimeHeader parses an authoritative server timestamp string.
// It supports standard HTTP Date header formats (RFC 1123, RFC 1123Z, RFC 850, ANSI C)
// as well as ISO 8601 / RFC 3339 timestamps and standard SQL dates.
func ParseServerTimeHeader(dateStr string) (time.Time, error) {
	s := strings.TrimSpace(dateStr)
	if s == "" {
		return time.Time{}, errors.New("license: empty server time header")
	}

	formats := []string{
		time.RFC1123,          // "Wed, 16 Sep 2026 10:00:00 GMT" (standard HTTP Date)
		time.RFC1123Z,         // "Wed, 16 Sep 2026 10:00:00 +0000"
		time.RFC3339,          // "2026-09-16T10:00:00Z"
		time.RFC3339Nano,      // "2026-09-16T10:00:00.999999999Z"
		time.RFC850,           // "Wednesday, 16-Sep-26 10:00:00 GMT"
		time.ANSIC,            // "Wed Sep 16 10:00:00 2026"
		"2006-01-02 15:04:05", // "2026-09-16 10:00:00"
		"2006-01-02",          // "2026-09-16"
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("license: unable to parse server time header %q", dateStr)
}

// WithAuthoritativeTime sets an authoritative reference time (e.g., from an HTTP Date header or cloud API)
// to defend against local system clock manipulation and false BSL conversion claims.
func WithAuthoritativeTime(t time.Time) ValidatorOption {
	return func(v *Validator) {
		v.authoritativeTime = t
	}
}

// WithRequireAuthoritativeTime enforces that an authoritative time source
// (e.g., via WithAuthoritativeTime, WithServerTimeAttestation, or WithServerTimeHeader)
// must be configured, failing closed with ErrMissingAuthoritativeTime if none is provided.
func WithRequireAuthoritativeTime(require bool) ValidatorOption {
	return func(v *Validator) {
		v.requireAuthoritativeTime = require
	}
}

// WithServerTimeAttestation validates licenses against an authoritative external server timestamp
// (e.g., from an HTTP response Date header, cloud metadata API, or central licensing service)
// with a configurable maximum allowed clock skew threshold.
//
// When clock skew between local host time and server time exceeds maxAllowedSkew, or if forward or backward
// clock tampering is detected, the validator anchors claims evaluation to the authoritative server time
// and flags clock tampering. If WithStrictClockDefense(true) is configured, verification fails immediately
// with ErrClockTamperingDetected.
func WithServerTimeAttestation(serverTime time.Time, maxAllowedSkew time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.authoritativeTime = serverTime
		if maxAllowedSkew > 0 {
			v.maxClockDrift = maxAllowedSkew
		}
		v.serverTimeAttested = true
	}
}

// WithServerTimeHeader parses an authoritative server timestamp from an HTTP Date header or
// ISO 8601 string and configures WithServerTimeAttestation. If headerValue cannot be parsed,
// it records an error on the validator to fail closed.
func WithServerTimeHeader(headerValue string, maxAllowedSkew time.Duration) ValidatorOption {
	return func(v *Validator) {
		t, err := ParseServerTimeHeader(headerValue)
		if err != nil {
			v.initErr = fmt.Errorf("%w: %v", ErrClockTamperingDetected, err)
			return
		}
		v.authoritativeTime = t
		if maxAllowedSkew > 0 {
			v.maxClockDrift = maxAllowedSkew
		}
		v.serverTimeAttested = true
	}
}

// WithStrictClockDefense controls whether clock tampering or excessive skew returns ErrClockTamperingDetected
// immediately rather than anchoring evaluation to the authoritative server time (default: false).
func WithStrictClockDefense(strict bool) ValidatorOption {
	return func(v *Validator) {
		v.strictClockDefense = strict
	}
}

// WithMaxClockDrift configures the tolerance threshold before the local clock is anchored to authoritative time (default: 1 hour).
func WithMaxClockDrift(drift time.Duration) ValidatorOption {
	return func(v *Validator) {
		v.maxClockDrift = drift
	}
}

func (v *Validator) effectiveBuildDate() time.Time {
	return v.effectiveBuildDateWithProv(nil)
}

func (v *Validator) effectiveBuildDateWithProv(prov *ReleaseProvenance) time.Time {
	if !v.buildDate.IsZero() {
		return v.buildDate
	}
	if prov != nil && prov.Attested && prov.Claims != nil {
		if !prov.Claims.BuildDate.IsZero() {
			return prov.Claims.BuildDate
		}
		if !prov.Claims.ReleaseDate.IsZero() {
			return prov.Claims.ReleaseDate
		}
	}
	if !IsPlaceholderAttestation(v.releaseAttestation) {
		if p, err := v.EvaluateProvenance(); err == nil && p != nil && p.Attested && p.Claims != nil {
			if !p.Claims.BuildDate.IsZero() {
				return p.Claims.BuildDate
			}
			if !p.Claims.ReleaseDate.IsZero() {
				return p.Claims.ReleaseDate
			}
		}
	}
	return time.Time{}
}

// resolveEvaluationTime reconciles the local reference time with any configured authoritative time,
// detecting forward and backward clock tampering attempts while respecting clock drift boundaries.
func (v *Validator) resolveEvaluationTime(localNow time.Time) (evalTime time.Time, tampered bool, skew time.Duration, err error) {
	return v.resolveEvaluationTimeWithProv(localNow, nil)
}

func (v *Validator) resolveEvaluationTimeWithProv(localNow time.Time, prov *ReleaseProvenance) (evalTime time.Time, tampered bool, skew time.Duration, err error) {
	evalTime = localNow
	localUTC := localNow.UTC()

	buildTime := v.effectiveBuildDateWithProv(prov)
	skewTolerance := v.clockSkew
	if skewTolerance < 0 {
		skewTolerance = 0
	}

	if v.authoritativeTime.IsZero() {
		if v.requireAuthoritativeTime {
			return localNow, false, 0, ErrMissingAuthoritativeTime
		}
		// Offline / air-gapped clock defense: local evaluation time cannot be physically prior to binary build date
		if !buildTime.IsZero() {
			earliest := buildTime.Add(-skewTolerance)
			if localUTC.Before(earliest) {
				drift := buildTime.Sub(localUTC)
				return localNow, true, drift, &ClockTamperingError{
					LocalTime:      localUTC,
					ServerTime:     buildTime.UTC(),
					Skew:           drift,
					MaxAllowedSkew: skewTolerance,
					Reason:         fmt.Sprintf("offline backward clock tampering detected: evaluation time %s is physically prior to binary build date %s", localUTC.Format(time.RFC3339), buildTime.UTC().Format(time.RFC3339)),
				}
			}
		}

		// Offline / air-gapped clock defense: autonomous BSL 1.1 open-source conversion
		// cannot be granted based solely on an unauthenticated local system clock.
		if v.bslPolicy != nil && v.bslPolicy.IsConverted(localUTC) && !v.serverTimeAttested {
			drift := time.Duration(0)
			serverAnchor := time.Time{}
			if !buildTime.IsZero() {
				drift = localUTC.Sub(buildTime)
				serverAnchor = buildTime.UTC()
			} else {
				changeDate := v.bslPolicy.ChangeDate()
				if !changeDate.IsZero() {
					drift = localUTC.Sub(changeDate)
				}
			}
			return localNow, true, drift, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     serverAnchor,
				Skew:           drift,
				MaxAllowedSkew: skewTolerance,
				Reason:         fmt.Sprintf("offline forward clock tampering detected: evaluation time %s claims BSL Change Date %s has arrived without authoritative time attestation", localUTC.Format(time.RFC3339), v.bslPolicy.ChangeDate().Format(time.RFC3339)),
			}
		}

		return evalTime, false, 0, nil
	}

	authTime := v.authoritativeTime.UTC()

	drift := localUTC.Sub(authTime)
	skew = drift
	if skew < 0 {
		skew = -drift
	}

	driftLimit := v.maxClockDrift
	if driftLimit <= 0 {
		driftLimit = time.Hour
	}

	// 1. Forward Clock Tampering Detection:
	// Local clock claims BSL Change Date has arrived, but authoritative server clock attests it has not!
	if v.bslPolicy != nil && v.bslPolicy.IsConverted(localUTC) && !v.bslPolicy.IsConverted(authTime) {
		tampered = true
		evalTime = authTime
		if v.strictClockDefense {
			return authTime, true, skew, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     authTime,
				Skew:           skew,
				MaxAllowedSkew: driftLimit,
				Reason:         "local clock advanced past BSL Change Date before authoritative server time",
			}
		}
		return evalTime, tampered, skew, nil
	}

	// 2. Significant Clock Drift / Tampering Check (Forward or Backward):
	if skew > driftLimit {
		tampered = true
		evalTime = authTime
		if v.strictClockDefense {
			reason := "local clock advanced too far ahead of server time"
			if drift < 0 {
				reason = "local clock set back in time behind server time"
			}
			return authTime, true, skew, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     authTime,
				Skew:           skew,
				MaxAllowedSkew: driftLimit,
				Reason:         reason,
			}
		}
		return evalTime, tampered, skew, nil
	}

	// 3. When server time is explicitly attested, always evaluate against the authoritative server time
	if v.serverTimeAttested {
		evalTime = authTime
	}

	// 4. Binary Build Date check: evaluation time cannot be physically prior to binary build date
	if !buildTime.IsZero() {
		earliest := buildTime.Add(-skewTolerance)
		if evalTime.Before(earliest) {
			drift := buildTime.Sub(evalTime)
			return evalTime, true, drift, &ClockTamperingError{
				LocalTime:      localUTC,
				ServerTime:     buildTime.UTC(),
				Skew:           drift,
				MaxAllowedSkew: skewTolerance,
				Reason:         fmt.Sprintf("backward clock tampering detected: evaluation time %s is physically prior to binary build date %s", evalTime.UTC().Format(time.RFC3339), buildTime.UTC().Format(time.RFC3339)),
			}
		}
	}

	return evalTime, tampered, skew, nil
}
