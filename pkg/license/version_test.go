package license_test

import (
	"errors"
	"testing"
	"time"

	"github.com/divmora/license-go/pkg/license"
)

func TestPerpetualLicense_MaxVersionWildcard(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	signer, err := license.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Issue Perpetual License locked to Version 1.*
	token, err := signer.Sign(license.Claims{
		Product: "gitlab-fleet-governor",
		Customer: license.Customer{
			Name: "Acme Corp (v1.x Perpetual)",
		},
		Plan:       "enterprise",
		MaxVersion: "1.*",
		// ExpiresAt is zero (perpetual)
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Validator running v1.0.0 -> PASS
	v1, err := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithCurrentVersion("1.0.0"),
	)
	if err != nil {
		t.Fatalf("NewValidator v1 failed: %v", err)
	}
	claims, err := v1.Verify(token)
	if err != nil {
		t.Fatalf("expected v1.0.0 to verify, got: %v", err)
	}
	if !claims.IsPerpetual() {
		t.Errorf("expected license to be perpetual")
	}

	// 2. Validator running v1.4.2 -> PASS
	v142, _ := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithCurrentVersion("v1.4.2"), // testing with leading 'v'
	)
	if _, err := v142.Verify(token); err != nil {
		t.Fatalf("expected v1.4.2 to verify, got: %v", err)
	}

	// 3. Validator running v2.0.0 -> FAIL (Upgrade not entitled!)
	v2, _ := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithCurrentVersion("2.0.0"),
	)
	_, err = v2.Verify(token)
	if !errors.Is(err, license.ErrVersionNotEntitled) {
		t.Fatalf("expected ErrVersionNotEntitled for v2.0.0 on a 1.* perpetual license, got: %v", err)
	}
}

func TestPerpetualLicense_MaxVersionSemVerBound(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	// License locked to <= 2.5.0
	token, err := signer.Sign(license.Claims{
		Product:    "otel-aws-log-processor",
		Customer:   license.Customer{Name: "Data Corp"},
		MaxVersion: "<=2.5.0",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// v2.5.0 -> PASS
	v250, _ := license.NewValidator(pub, license.WithCurrentVersion("2.5.0"))
	if _, err := v250.Verify(token); err != nil {
		t.Fatalf("expected v2.5.0 to verify, got: %v", err)
	}

	// v2.4.9 -> PASS
	v249, _ := license.NewValidator(pub, license.WithCurrentVersion("2.4.9"))
	if _, err := v249.Verify(token); err != nil {
		t.Fatalf("expected v2.4.9 to verify, got: %v", err)
	}

	// v2.5.1 -> FAIL
	v251, _ := license.NewValidator(pub, license.WithCurrentVersion("2.5.1"))
	_, err = v251.Verify(token)
	if !errors.Is(err, license.ErrVersionNotEntitled) {
		t.Fatalf("expected ErrVersionNotEntitled for v2.5.1 on <=2.5.0 license, got: %v", err)
	}
}

func TestPerpetualLicense_AllowedVersionsList(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	// License allows 1.* and 2.0.*
	token, err := signer.Sign(license.Claims{
		Product:         "gitlab-fleet-governor",
		Customer:        license.Customer{Name: "Multi-Version Licensee"},
		AllowedVersions: []string{"1.*", "2.0.*"},
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// v1.9.0 -> PASS
	v19, _ := license.NewValidator(pub, license.WithCurrentVersion("1.9.0"))
	if _, err := v19.Verify(token); err != nil {
		t.Fatalf("expected v1.9.0 to pass, got: %v", err)
	}

	// v2.0.3 -> PASS
	v203, _ := license.NewValidator(pub, license.WithCurrentVersion("2.0.3"))
	if _, err := v203.Verify(token); err != nil {
		t.Fatalf("expected v2.0.3 to pass, got: %v", err)
	}

	// v2.1.0 -> FAIL
	v210, _ := license.NewValidator(pub, license.WithCurrentVersion("2.1.0"))
	_, err = v210.Verify(token)
	if !errors.Is(err, license.ErrVersionNotEntitled) {
		t.Fatalf("expected ErrVersionNotEntitled for v2.1.0, got: %v", err)
	}
}

func TestPerpetualLicense_MaintenanceCutoffDate(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	// Perpetual license issued today with 1 year of maintenance updates included
	issuedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	maintenanceCutoff := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)

	token, err := signer.Sign(license.Claims{
		Product:              "gitlab-fleet-governor",
		Customer:             license.Customer{Name: "Enterprise Customer"},
		IssuedAt:             issuedAt,
		MaintenanceExpiresAt: maintenanceCutoff,
		// ExpiresAt zero -> perpetual runtime
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Binary built in June 2026 (during maintenance window) -> PASS
	buildJune2026 := time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC)
	valValid, _ := license.NewValidator(pub, license.WithBuildDate(buildJune2026))
	claims, err := valValid.Verify(token)
	if err != nil {
		t.Fatalf("expected binary built during maintenance window to verify, got: %v", err)
	}
	if !claims.IsMaintenanceActiveAt(buildJune2026) {
		t.Errorf("expected IsMaintenanceActiveAt to be true")
	}

	// 2. Binary built in March 2027 (after maintenance window expired) -> FAIL with ErrMaintenanceExpired
	buildMarch2027 := time.Date(2027, time.March, 1, 10, 0, 0, 0, time.UTC)
	valExpired, _ := license.NewValidator(pub, license.WithBuildDate(buildMarch2027))
	_, err = valExpired.Verify(token)
	if !errors.Is(err, license.ErrMaintenanceExpired) {
		t.Fatalf("expected ErrMaintenanceExpired for binary built after maintenance cutoff, got: %v", err)
	}
}

func TestPerpetualLicense_CombinedVersionAndMaintenance(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	maintenanceCutoff := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)

	token, err := signer.Sign(license.Claims{
		Product:              "otel-aws-log-processor",
		Customer:             license.Customer{Name: "Airgapped Finance"},
		MaxVersion:           "1.*",
		MaintenanceExpiresAt: maintenanceCutoff,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Correct version AND inside maintenance date -> PASS
	val1, _ := license.NewValidator(pub,
		license.WithCurrentVersion("1.3.0"),
		license.WithBuildDate(time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)),
	)
	if _, err := val1.Verify(token); err != nil {
		t.Fatalf("expected valid version and build date to verify, got: %v", err)
	}

	// Exceeded version (v2.0.0) -> FAILS on version
	val2, _ := license.NewValidator(pub,
		license.WithCurrentVersion("2.0.0"),
		license.WithBuildDate(time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)),
	)
	_, err = val2.Verify(token)
	if !errors.Is(err, license.ErrVersionNotEntitled) {
		t.Fatalf("expected ErrVersionNotEntitled, got: %v", err)
	}

	// Valid version (v1.5.0) but built after maintenance cutoff -> FAILS on maintenance
	val3, _ := license.NewValidator(pub,
		license.WithCurrentVersion("1.5.0"),
		license.WithBuildDate(time.Date(2027, time.August, 1, 0, 0, 0, 0, time.UTC)),
	)
	_, err = val3.Verify(token)
	if !errors.Is(err, license.ErrMaintenanceExpired) {
		t.Fatalf("expected ErrMaintenanceExpired, got: %v", err)
	}
}

func TestPerpetualLicense_WildcardMinorVersionBounds(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := license.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Issue Perpetual License locked to Version 1.2.*
	token, err := signer.Sign(license.Claims{
		Product:    "gitlab-fleet-governor",
		Customer:   license.Customer{Name: "Acme Minor Lock"},
		Plan:       "enterprise",
		MaxVersion: "1.2.*",
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	testCases := []struct {
		version string
		allowed bool
	}{
		{"0.9.0", true},
		{"1.0.0", true},
		{"1.1.9", true},
		{"1.2.0", true},
		{"v1.2.5", true},
		{"1.2.99", true},
		{"1.2", true},
		{"1.3.0", false}, // Exceeds minor 2!
		{"1.3.1", false},
		{"1.99.0", false}, // Must not allow 1.99.0 on a 1.2.* license!
		{"2.0.0", false},
	}

	for _, tc := range testCases {
		t.Run("ver_"+tc.version, func(t *testing.T) {
			v, err := license.NewValidator(pub,
				license.WithProduct("gitlab-fleet-governor"),
				license.WithCurrentVersion(tc.version),
			)
			if err != nil {
				t.Fatalf("NewValidator failed: %v", err)
			}
			_, err = v.Verify(token)
			if tc.allowed && err != nil {
				t.Errorf("expected version %s to be allowed on 1.2.*, but got: %v", tc.version, err)
			}
			if !tc.allowed && err == nil {
				t.Errorf("expected version %s to be REJECTED on 1.2.*, but it was accepted!", tc.version)
			}
		})
	}
}

func TestPerpetualLicense_WildcardMinorVersionWithX(t *testing.T) {
	claims := license.Claims{
		Product:    "gitlab-fleet-governor",
		MaxVersion: "1.2.x",
	}

	if !claims.IsVersionAllowed("1.2.0") {
		t.Errorf("expected 1.2.0 to be allowed on 1.2.x")
	}
	if !claims.IsVersionAllowed("1.2.8") {
		t.Errorf("expected 1.2.8 to be allowed on 1.2.x")
	}
	if !claims.IsVersionAllowed("1.1.5") {
		t.Errorf("expected 1.1.5 to be allowed on 1.2.x")
	}
	if claims.IsVersionAllowed("1.3.0") {
		t.Errorf("expected 1.3.0 to be REJECTED on 1.2.x")
	}
	if claims.IsVersionAllowed("1.99.0") {
		t.Errorf("expected 1.99.0 to be REJECTED on 1.2.x")
	}
	if claims.IsVersionAllowed("2.0.0") {
		t.Errorf("expected 2.0.0 to be REJECTED on 1.2.x")
	}
}

func TestPerpetualLicense_StrictLessThan(t *testing.T) {
	claims := license.Claims{
		Product:    "gitlab-fleet-governor",
		MaxVersion: "<2.0.0",
	}

	if !claims.IsVersionAllowed("1.9.9") {
		t.Errorf("expected 1.9.9 to be allowed on <2.0.0")
	}
	if claims.IsVersionAllowed("2.0.0") {
		t.Errorf("expected 2.0.0 to be REJECTED on <2.0.0")
	}
	if claims.IsVersionAllowed("2.0.1") {
		t.Errorf("expected 2.0.1 to be REJECTED on <2.0.0")
	}

	// Wildcard with strict less than: <2.*
	claimsWild := license.Claims{
		Product:    "gitlab-fleet-governor",
		MaxVersion: "<2.*",
	}
	if !claimsWild.IsVersionAllowed("1.99.0") {
		t.Errorf("expected 1.99.0 to be allowed on <2.*")
	}
	if claimsWild.IsVersionAllowed("2.0.0") {
		t.Errorf("expected 2.0.0 to be REJECTED on <2.*")
	}
}

func TestPerpetualLicense_LeadingVPrefix(t *testing.T) {
	claims := license.Claims{
		Product:    "gitlab-fleet-governor",
		MaxVersion: "<=v2.5.0",
	}

	if !claims.IsVersionAllowed("v2.5.0") {
		t.Errorf("expected v2.5.0 to be allowed on <=v2.5.0")
	}
	if !claims.IsVersionAllowed("2.5.0") {
		t.Errorf("expected 2.5.0 to be allowed on <=v2.5.0")
	}
	if claims.IsVersionAllowed("v2.5.1") {
		t.Errorf("expected v2.5.1 to be REJECTED on <=v2.5.0")
	}
}
