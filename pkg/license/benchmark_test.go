package license_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func BenchmarkValidatorVerify_Enterprise(b *testing.B) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	now := time.Now().UTC()
	claims := license.Claims{
		ID: "bench-enterprise-lic",
		Customer: license.Customer{
			Name:  "Benchmark Enterprise",
			Email: "benchmark@example.com",
		},
		Product:   "gitlab-fleet-governor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		Features:  []string{"ha", "audit-logs", "sso", "compliance.*"},
		Limits: map[string]int64{
			"runners": 100,
			"nodes":   25,
		},
		Scope: &license.Scope{
			Environments: []string{"production", "staging"},
			Regions:      []string{"us-east-1", "eu-west-1"},
		},
	}
	token, _ := signer.Sign(claims)
	validator, _ := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithEnvironment("production"),
		license.WithCurrentRegion("us-east-1"),
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := validator.Verify(token)
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}

func BenchmarkValidatorVerify_Community(b *testing.B) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	now := time.Now().UTC()
	claims := license.Claims{
		ID: "bench-community-lic",
		Customer: license.Customer{
			Name: "Community User",
		},
		Product:   "gitlab-fleet-governor",
		Plan:      "community",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		Features:  []string{"basic-monitoring"},
		Limits: map[string]int64{
			"runners": 5,
		},
	}
	token, _ := signer.Sign(claims)
	validator, _ := license.NewValidator(pub, license.WithProduct("gitlab-fleet-governor"))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := validator.Verify(token)
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}

func BenchmarkValidatorVerify_Perpetual(b *testing.B) {
	pub, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)

	now := time.Now().UTC()
	claims := license.Claims{
		ID: "bench-perpetual-lic",
		Customer: license.Customer{
			Name: "Perpetual Customer",
		},
		Product:    "gitlab-fleet-governor",
		Plan:       "perpetual",
		IssuedAt:   now,
		MaxVersion: "<=2.5.0",
		Features:   []string{"*"},
	}
	token, _ := signer.Sign(claims)
	validator, _ := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithCurrentVersion("2.4.1"),
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := validator.Verify(token)
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}

func BenchmarkValidatorVerify_BSLConverted(b *testing.B) {
	pub, _, _ := license.GenerateKeyPair()
	releaseDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := license.BSLPolicy{
		ReleaseDate:       releaseDate,
		ChangePeriodYears: 3,
		Product:           "gitlab-fleet-governor",
	}
	validator, _ := license.NewValidator(pub,
		license.WithProduct("gitlab-fleet-governor"),
		license.WithBSLPolicy(policy),
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := validator.Verify("")
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}

func BenchmarkKeyRingVerify(b *testing.B) {
	pub, priv, _ := license.GenerateKeyPair()
	kr := license.NewKeyRing(pub)

	data := []byte("DIV1.eyJwcm9kdWN0IjoiZ2l0bGFiLWZsZWV0LWdvdmVybm9yIn0")
	sig := ed25519.Sign(priv, data)
	keyID := license.KeyFingerprint(pub)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kr.VerifySignature(data, sig, keyID)
		if err != nil {
			b.Fatalf("VerifySignature failed: %v", err)
		}
	}
}

func BenchmarkParseToken(b *testing.B) {
	_, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)
	now := time.Now().UTC()
	token, _ := signer.Sign(license.Claims{
		ID: "bench-parse-token",
		Customer: license.Customer{
			Name: "Acme",
		},
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		IssuedAt: now,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, err := license.ParseToken(token)
		if err != nil {
			b.Fatalf("ParseToken failed: %v", err)
		}
	}
}

func BenchmarkUnwrapToken(b *testing.B) {
	_, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)
	now := time.Now().UTC()
	compactToken, _ := signer.Sign(license.Claims{
		ID: "bench-unwrap-token",
		Customer: license.Customer{
			Name: "Acme",
		},
		Product:  "gitlab-fleet-governor",
		Plan:     "enterprise",
		IssuedAt: now,
	})
	armoredToken := license.WrapArmored(compactToken)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := license.UnwrapToken(armoredToken)
		if err != nil {
			b.Fatalf("UnwrapToken failed: %v", err)
		}
	}
}

func BenchmarkSignerSign(b *testing.B) {
	_, priv, _ := license.GenerateKeyPair()
	signer, _ := license.NewSigner(priv)
	now := time.Now().UTC()
	claims := license.Claims{
		ID: "bench-signer-sign",
		Customer: license.Customer{
			Name:  "Acme Corp",
			Email: "admin@acme.com",
		},
		Product:   "gitlab-fleet-governor",
		Plan:      "enterprise",
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		Features:  []string{"ha", "audit-logs"},
		Limits: map[string]int64{
			"runners": 50,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(claims)
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
	}
}

func BenchmarkClaimsHasFeature(b *testing.B) {
	claims := license.Claims{
		Features: []string{"audit-logs", "compliance.*", "sso", "ha"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = claims.HasFeature("compliance.soc2")
	}
}

func BenchmarkClaimsCheckLimit(b *testing.B) {
	claims := license.Claims{
		Limits: map[string]int64{
			"runners": 100,
			"nodes":   50,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = claims.CheckLimit("runners", 42)
	}
}

func BenchmarkClaimsIsInScope(b *testing.B) {
	claims := license.Claims{
		Scope: &license.Scope{
			Environments: []string{"production", "staging"},
			Regions:      []string{"us-east-1", "eu-west-1", "ap-southeast-1"},
			Clusters:     []string{"k8s-prod-*"},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = claims.IsInScope("clusters", "k8s-prod-us1")
	}
}
