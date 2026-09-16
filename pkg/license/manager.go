package license

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// DefaultManagerCheckInterval is the default periodic check frequency.
const DefaultManagerCheckInterval = 1 * time.Hour

// DefaultExpiryWarningDays is the default threshold in days to trigger expiration warnings.
const DefaultExpiryWarningDays = 14

// ManagerConfig provides configuration parameters for the background License Manager.
type ManagerConfig struct {
	// Validator is the license validator configured with product and public key. (Required)
	Validator *Validator

	// LicenseFile is the file path to load and watch for hot reloads.
	LicenseFile string

	// LicenseString is the raw license token or armored block (used if LicenseFile is empty).
	LicenseString string

	// CheckInterval configures how often the license status and file are checked.
	// Defaults to 1 hour if not specified.
	CheckInterval time.Duration

	// ExpiryWarningDays triggers OnExpiringSoon when days remaining is less than or equal to this value.
	// Defaults to 14 days if not specified.
	ExpiryWarningDays int

	// OnExpiringSoon is called when an active license is approaching expiration.
	OnExpiringSoon func(claims *Claims, daysRemaining int)

	// OnGracePeriod is called when an active license is operating within its grace period.
	OnGracePeriod func(claims *Claims, graceDaysRemaining int)

	// OnExpired is called when the license transitions to expired (or exceeds its grace period).
	OnExpired func(claims *Claims)

	// OnReloaded is called when a new valid license is detected and reloaded from disk.
	OnReloaded func(newClaims *Claims, oldClaims *Claims)

	// OnError is called if periodic validation or file reloading encounters an error.
	OnError func(err error)
}

// Manager manages license state, periodic expiration monitoring, and hot reloading for long-running services.
type Manager struct {
	cfg              ManagerConfig
	mu               sync.RWMutex
	currentClaims    *Claims
	currentLicense   string
	lastModTime      time.Time
	hasNotifiedExp   bool
	hasNotifiedGrace bool
	lastWarnedDays   int

	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewManager creates and initializes a new license Manager, verifying the initial license immediately.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Validator == nil {
		return nil, errors.New("license: validator is required for manager")
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultManagerCheckInterval
	}
	if cfg.ExpiryWarningDays <= 0 {
		cfg.ExpiryWarningDays = DefaultExpiryWarningDays
	}

	// Auto-resolve from environment (DIVMORA_LICENSE_FILE, DIVMORA_LICENSE_KEY, or /etc/divmora/license.key)
	// if neither LicenseFile nor LicenseString was provided.
	if cfg.LicenseFile == "" && cfg.LicenseString == "" {
		resolved, err := ResolveLicense()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve license source: %w", err)
		}
		if resolved.FilePath != "" {
			cfg.LicenseFile = resolved.FilePath
		} else {
			cfg.LicenseString = resolved.Content
		}
	}

	m := &Manager{
		cfg:            cfg,
		stopChan:       make(chan struct{}),
		lastWarnedDays: -1,
	}

	// Initial load and verification
	if err := m.loadAndVerify(true); err != nil {
		return nil, fmt.Errorf("initial license verification failed: %w", err)
	}

	return m, nil
}

// Start launches the background monitoring goroutine.
func (m *Manager) Start(ctx context.Context) {
	m.wg.Add(1)
	go m.run(ctx)
}

// Stop shuts down the background monitoring goroutine.
func (m *Manager) Stop() {
	select {
	case <-m.stopChan:
		return
	default:
		close(m.stopChan)
	}
	m.wg.Wait()
}

// Claims returns a thread-safe copy of the active license claims.
func (m *Manager) Claims() *Claims {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentClaims
}

// HasFeature returns whether the specified feature is entitled in the active license.
func (m *Manager) HasFeature(feature string) bool {
	claims := m.Claims()
	if claims == nil {
		return false
	}
	return claims.HasFeature(feature)
}

// CheckLimit checks if current usage is within the active license limits.
func (m *Manager) CheckLimit(limitName string, currentUsage int64) error {
	claims := m.Claims()
	if claims == nil {
		return ErrLicenseNotFound
	}
	return claims.CheckLimit(limitName, currentUsage)
}

// IsActive returns whether the active license is currently valid and unexpired.
func (m *Manager) IsActive() bool {
	claims := m.Claims()
	if claims == nil {
		return false
	}
	return claims.IsActive()
}

// run is the background ticker loop.
func (m *Manager) run(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.check()
		}
	}
}

// check executes periodic inspection, checking for file updates and expiration triggers.
func (m *Manager) check() {
	// 1. Check for file reload if file-backed
	if m.cfg.LicenseFile != "" {
		if err := m.loadAndVerify(false); err != nil {
			if m.cfg.OnError != nil {
				m.cfg.OnError(err)
			}
		}
	}

	// 2. Check expiration & grace period status
	claims := m.Claims()
	if claims == nil {
		return
	}

	// Check if currently operating in grace period
	if claims.IsInGracePeriod() {
		m.mu.Lock()
		if !m.hasNotifiedGrace {
			m.hasNotifiedGrace = true
			m.mu.Unlock()
			if m.cfg.OnGracePeriod != nil {
				m.cfg.OnGracePeriod(claims, claims.GraceDaysRemaining())
			}
		} else {
			m.mu.Unlock()
		}
		return
	}

	// Check if completely expired
	if claims.IsExpired() {
		m.mu.Lock()
		if !m.hasNotifiedExp {
			m.hasNotifiedExp = true
			m.mu.Unlock()
			if m.cfg.OnExpired != nil {
				m.cfg.OnExpired(claims)
			}
		} else {
			m.mu.Unlock()
		}
		return
	}

	// Active license: check days remaining
	days := claims.DaysRemaining()
	if days >= 0 && days <= m.cfg.ExpiryWarningDays {
		m.mu.Lock()
		shouldNotify := m.lastWarnedDays != days
		m.lastWarnedDays = days
		m.mu.Unlock()

		if shouldNotify && m.cfg.OnExpiringSoon != nil {
			m.cfg.OnExpiringSoon(claims, days)
		}
	}
}

// loadAndVerify loads license data from file or string and validates it.
func (m *Manager) loadAndVerify(initial bool) error {
	var rawData string
	var modTime time.Time

	if m.cfg.LicenseFile != "" {
		info, err := os.Stat(m.cfg.LicenseFile)
		if err != nil {
			return fmt.Errorf("failed to stat license file: %w", err)
		}

		if !initial && !info.ModTime().After(m.lastModTime) {
			// File has not been modified since last check
			return nil
		}

		bytes, err := os.ReadFile(m.cfg.LicenseFile)
		if err != nil {
			return fmt.Errorf("failed to read license file: %w", err)
		}
		rawData = string(bytes)
		modTime = info.ModTime()
	} else {
		rawData = m.cfg.LicenseString
	}

	if rawData == "" {
		return ErrLicenseNotFound
	}

	m.mu.RLock()
	isSameLicense := rawData == m.currentLicense
	oldClaims := m.currentClaims
	m.mu.RUnlock()

	if !initial && isSameLicense {
		m.mu.Lock()
		m.lastModTime = modTime
		m.mu.Unlock()
		return nil
	}

	newClaims, err := m.cfg.Validator.Verify(rawData)
	if err != nil {
		return fmt.Errorf("license verification failed: %w", err)
	}

	m.mu.Lock()
	m.currentClaims = newClaims
	m.currentLicense = rawData
	m.lastModTime = modTime
	m.hasNotifiedExp = false
	m.hasNotifiedGrace = false
	m.lastWarnedDays = -1
	m.mu.Unlock()

	if !initial && m.cfg.OnReloaded != nil {
		m.cfg.OnReloaded(newClaims, oldClaims)
	}

	return nil
}
