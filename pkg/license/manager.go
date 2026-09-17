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

// EnforcementPolicy defines how the Manager handles license expiration, missing licenses, or verification failures.
type EnforcementPolicy string

const (
	// PolicyStrict fails closed and halts operations upon license expiration, missing license, or validation errors (Default).
	PolicyStrict EnforcementPolicy = "strict"

	// PolicyDegraded falls back to community/free-tier claims or read-only mode, logging warnings instead of halting critical services.
	PolicyDegraded EnforcementPolicy = "degraded"

	// PolicyWarnOnly permits all operations unconditionally while recording and alerting on policy violations (audit/dry-run mode).
	PolicyWarnOnly EnforcementPolicy = "warn_only"
)

// DefaultCommunityClaims returns standard community-tier claims for a given product.
func DefaultCommunityClaims(product string) *Claims {
	if product == "" {
		product = "divmora-product"
	}
	return &Claims{
		Product:  product,
		Plan:     "community",
		Customer: Customer{Name: "Community User"},
		Features: []string{"community"},
		Limits:   map[string]int64{},
	}
}

// ManagerConfig provides configuration parameters for the background License Manager.
type ManagerConfig struct {
	// Validator is the license validator configured with product and public key. (Required)
	Validator *Validator

	// LicenseFile is the file path to load and watch for hot reloads.
	LicenseFile string

	// LicenseString is the raw license token or armored block (used if LicenseFile is empty).
	LicenseString string

	// Policy defines the operational enforcement mode (PolicyStrict, PolicyDegraded, PolicyWarnOnly).
	// Defaults to PolicyStrict if not specified.
	Policy EnforcementPolicy

	// FallbackClaims provides the fallback entitlements (e.g., community tier) used when operating in PolicyDegraded.
	// If nil in PolicyDegraded or PolicyWarnOnly, default community tier claims are automatically provided.
	FallbackClaims *Claims

	// DegradedReadOnly restricts write operations (CanMutate returns ErrDegradedReadOnly) when in degraded mode.
	DegradedReadOnly bool

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

	// OnDegraded is called when the manager enters degraded mode due to expiration, missing license, or verification errors.
	OnDegraded func(reason error, claims *Claims)

	// OnRecovered is called when the manager recovers from degraded mode back to an active licensed state.
	OnRecovered func(newClaims *Claims)

	// OnBSLConverted is called when the BSL 1.1 Change Date arrives and the service converts to Apache 2.0.
	OnBSLConverted func(claims *Claims)

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
	hasNotifiedBSL   bool
	isDegraded       bool
	degradedReason   error
	lastWarnedDays   int

	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewManager creates and initializes a new license Manager, verifying the initial license immediately.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Validator == nil {
		return nil, errors.New("license: validator is required for manager")
	}
	if cfg.Policy == "" {
		cfg.Policy = PolicyStrict
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultManagerCheckInterval
	}
	if cfg.ExpiryWarningDays <= 0 {
		cfg.ExpiryWarningDays = DefaultExpiryWarningDays
	}

	// In PolicyDegraded or PolicyWarnOnly, populate default community claims if none provided
	if (cfg.Policy == PolicyDegraded || cfg.Policy == PolicyWarnOnly) && cfg.FallbackClaims == nil {
		cfg.FallbackClaims = DefaultCommunityClaims(cfg.Validator.ExpectedProduct())
	}

	// Auto-resolve from environment (DIVMORA_LICENSE_FILE, DIVMORA_LICENSE_KEY, or /etc/divmora/license.key)
	// if neither LicenseFile nor LicenseString was provided.
	if cfg.LicenseFile == "" && cfg.LicenseString == "" {
		resolved, err := ResolveLicense()
		if err != nil {
			if cfg.Policy == PolicyStrict {
				return nil, fmt.Errorf("failed to resolve license source: %w", err)
			}
			// In PolicyDegraded or PolicyWarnOnly, do not fail initialization;
			// continue with empty license to trigger degraded fallback.
		} else {
			if resolved.FilePath != "" {
				cfg.LicenseFile = resolved.FilePath
			} else {
				cfg.LicenseString = resolved.Content
			}
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

// Policy returns the configured enforcement policy mode.
func (m *Manager) evalTime() (time.Time, error) {
	if m.cfg.Validator == nil {
		return time.Now(), nil
	}
	evalTime, _, _, err := m.cfg.Validator.resolveEvaluationTime(time.Now())
	return evalTime, err
}

func (m *Manager) Policy() EnforcementPolicy {
	return m.cfg.Policy
}

// Claims returns a thread-safe copy of the active license claims (or fallback claims if degraded).
func (m *Manager) Claims() *Claims {
	m.mu.RLock()
	defer m.mu.RUnlock()
	evalTime, _ := m.evalTime()
	if m.cfg.Policy == PolicyDegraded && m.currentClaims != nil && !m.currentClaims.IsActiveAt(evalTime) && m.cfg.FallbackClaims != nil {
		return m.cfg.FallbackClaims
	}
	return m.currentClaims
}

// IsDegraded reports whether the manager is currently operating in degraded fallback mode.
func (m *Manager) IsDegraded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.isDegraded {
		return true
	}
	evalTime, _ := m.evalTime()
	if m.cfg.Policy == PolicyDegraded && m.currentClaims != nil && !m.currentClaims.IsActiveAt(evalTime) {
		return true
	}
	return false
}

// DegradedReason returns the error that triggered degraded mode, or nil if operating normally.
func (m *Manager) DegradedReason() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.degradedReason != nil {
		return m.degradedReason
	}
	evalTime, _ := m.evalTime()
	if m.cfg.Policy == PolicyDegraded && m.currentClaims != nil && !m.currentClaims.IsActiveAt(evalTime) {
		return ErrExpired
	}
	return nil
}

// IsReadOnly reports whether write operations are restricted due to degraded mode.
func (m *Manager) IsReadOnly() bool {
	return m.IsDegraded() && m.cfg.DegradedReadOnly
}

// CanMutate checks whether mutations/write operations are allowed.
// Returns ErrDegradedReadOnly if operating in degraded read-only mode,
// ErrLicenseNotFound if no license claims exist, ErrNotYetValid if the license is not yet active,
// or ErrExpired if inactive in strict mode.
func (m *Manager) CanMutate() error {
	if m.IsReadOnly() {
		return ErrDegradedReadOnly
	}
	if m.cfg.Policy == PolicyWarnOnly {
		return nil
	}
	if !m.IsActive() {
		claims := m.Claims()
		if claims == nil {
			return ErrLicenseNotFound
		}
		evalTime, _ := m.evalTime()
		if claims.StatusAt(evalTime) == StatusNotYetValid {
			return ErrNotYetValid
		}
		return ErrExpired
	}
	return nil
}

// HasFeature returns whether the specified feature is entitled in the active license (or fallback claims).
// If the license is expired, inactive, or not found under PolicyStrict, this returns false.
// Under PolicyWarnOnly, this unconditionally returns true.
func (m *Manager) HasFeature(feature string) bool {
	if m.cfg.Policy == PolicyWarnOnly {
		return true
	}
	if !m.IsActive() {
		return false
	}
	claims := m.Claims()
	if claims == nil {
		return false
	}
	return claims.HasFeature(feature)
}

// AssertFeature asserts that the specified feature is active and entitled in the current license (or fallback claims).
// Returns nil if entitled, ErrExpired if the license has expired, ErrNotYetValid if the license is not yet active,
// ErrLicenseNotFound if no claims exist, or ErrFeatureNotEntitled if the feature is not granted.
// Under PolicyWarnOnly, this unconditionally returns nil.
func (m *Manager) AssertFeature(feature string) error {
	if m.cfg.Policy == PolicyWarnOnly {
		return nil
	}
	claims := m.Claims()
	if claims == nil {
		return ErrLicenseNotFound
	}
	if !m.IsActive() {
		evalTime, _ := m.evalTime()
		if claims.StatusAt(evalTime) == StatusNotYetValid {
			return ErrNotYetValid
		}
		return ErrExpired
	}
	return claims.AssertFeature(feature)
}

// CheckLimit checks if current usage is within the active license limits (or fallback limits if degraded).
// If the license is inactive (expired, not yet valid, or not found) under PolicyStrict, this returns an error.
// Under PolicyWarnOnly, this unconditionally returns nil.
func (m *Manager) CheckLimit(limitName string, currentUsage int64) error {
	if m.cfg.Policy == PolicyWarnOnly {
		return nil
	}
	claims := m.Claims()
	if claims == nil {
		return ErrLicenseNotFound
	}
	if !m.IsActive() {
		evalTime, _ := m.evalTime()
		if claims.StatusAt(evalTime) == StatusNotYetValid {
			return ErrNotYetValid
		}
		return ErrExpired
	}
	return claims.CheckLimit(limitName, currentUsage)
}

// IsActive returns whether the service is currently operational.
// Under PolicyStrict, this returns true only if a valid, unexpired license is active.
// Under PolicyDegraded, this returns true even when degraded, because fallback claims permit execution.
// Under PolicyWarnOnly, this unconditionally returns true.
func (m *Manager) IsActive() bool {
	if m.cfg.Policy == PolicyWarnOnly {
		return true
	}
	claims := m.Claims()
	if claims == nil {
		return false
	}
	if m.cfg.Policy == PolicyStrict {
		m.mu.RLock()
		degraded := m.isDegraded
		m.mu.RUnlock()
		if degraded {
			return false
		}
		evalTime, err := m.evalTime()
		if err != nil {
			return false
		}
		return claims.IsActiveAt(evalTime)
	}
	return true
}

// IsCommercialActive returns whether a genuine commercial license is currently active (not degraded).
func (m *Manager) IsCommercialActive() bool {
	if m.IsDegraded() {
		return false
	}
	claims := m.Claims()
	if claims == nil {
		return false
	}
	m.mu.RLock()
	degraded := m.isDegraded
	m.mu.RUnlock()
	if degraded {
		return false
	}
	evalTime, err := m.evalTime()
	if err != nil {
		return false
	}
	return claims.IsActiveAt(evalTime)
}

// Check triggers an immediate inspection and verification cycle synchronously.
func (m *Manager) Check() {
	m.check()
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

// check executes periodic inspection, checking for file updates, BSL conversion, and expiration triggers.
func (m *Manager) check() {
	// 1. Check for file reload if file-backed
	if m.cfg.LicenseFile != "" {
		if err := m.loadAndVerify(false); err != nil {
			if m.cfg.OnError != nil {
				m.cfg.OnError(err)
			}
		}
	}

	evalTime, err := m.evalTime()
	if err != nil {
		if m.cfg.OnError != nil {
			m.cfg.OnError(err)
		}
		if m.cfg.Policy == PolicyDegraded {
			m.transitionToDegraded(err)
		}
		return
	}

	// 2. Check BSL 1.1 Change Date conversion
	if bsl := m.cfg.Validator.BSLPolicy(); bsl != nil && bsl.IsConverted(evalTime) {
		m.mu.Lock()
		if !m.hasNotifiedBSL {
			m.hasNotifiedBSL = true
			wasDegraded := m.isDegraded
			m.isDegraded = false
			m.degradedReason = nil
			m.currentClaims = &Claims{
				Product:  m.cfg.Validator.ExpectedProduct(),
				Plan:     "open-source",
				Customer: Customer{Name: "Open Source Community"},
				Features: []string{"*"},
				Limits:   map[string]int64{},
			}
			openClaims := m.currentClaims
			m.mu.Unlock()

			if wasDegraded && m.cfg.OnRecovered != nil {
				m.cfg.OnRecovered(openClaims)
			}
			if m.cfg.OnBSLConverted != nil {
				m.cfg.OnBSLConverted(openClaims)
			}
		} else {
			m.mu.Unlock()
		}
		return
	}

	// 3. Check expiration & grace period status
	m.mu.RLock()
	degraded := m.isDegraded
	claims := m.currentClaims
	m.mu.RUnlock()

	if claims == nil || degraded {
		return
	}

	// Check if currently operating in grace period
	if claims.IsInGracePeriodAt(evalTime) {
		m.mu.Lock()
		if !m.hasNotifiedGrace {
			m.hasNotifiedGrace = true
			m.mu.Unlock()
			if m.cfg.OnGracePeriod != nil {
				m.cfg.OnGracePeriod(claims, claims.GraceDaysRemainingAt(evalTime))
			}
		} else {
			m.mu.Unlock()
		}
		return
	}

	// Check if completely expired
	if claims.IsExpiredAt(evalTime) {
		m.mu.Lock()
		shouldNotifyExp := !m.hasNotifiedExp
		m.hasNotifiedExp = true
		m.mu.Unlock()

		if shouldNotifyExp && m.cfg.OnExpired != nil {
			m.cfg.OnExpired(claims)
		}

		// In PolicyDegraded, transition to degraded fallback mode
		if m.cfg.Policy == PolicyDegraded {
			m.transitionToDegraded(ErrExpired)
		}
		return
	}

	// Active license: check days remaining
	days := claims.DaysRemainingAt(evalTime)
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

func (m *Manager) transitionToDegraded(reason error) {
	m.mu.Lock()
	wasDegraded := m.isDegraded
	m.isDegraded = true
	m.degradedReason = reason
	if m.cfg.FallbackClaims != nil {
		m.currentClaims = m.cfg.FallbackClaims
	}
	claims := m.currentClaims
	m.mu.Unlock()

	if !wasDegraded && m.cfg.OnDegraded != nil {
		m.cfg.OnDegraded(reason, claims)
	}
}

func (m *Manager) transitionToRecovered(newClaims *Claims, oldClaims *Claims) {
	m.mu.Lock()
	wasDegraded := m.isDegraded
	m.isDegraded = false
	m.degradedReason = nil
	m.currentClaims = newClaims
	m.hasNotifiedExp = false
	m.hasNotifiedGrace = false
	m.lastWarnedDays = -1
	m.mu.Unlock()

	if wasDegraded && m.cfg.OnRecovered != nil {
		m.cfg.OnRecovered(newClaims)
	}
	if m.cfg.OnReloaded != nil {
		m.cfg.OnReloaded(newClaims, oldClaims)
	}
}

// loadAndVerify loads license data from file or string and validates it.
func (m *Manager) loadAndVerify(initial bool) error {
	var rawData string
	var modTime time.Time

	if m.cfg.LicenseFile != "" {
		info, err := os.Stat(m.cfg.LicenseFile)
		if err != nil {
			if m.cfg.Policy == PolicyDegraded || m.cfg.Policy == PolicyWarnOnly {
				m.transitionToDegraded(err)
				return nil
			}
			return fmt.Errorf("failed to stat license file: %w", err)
		}

		if !initial && !info.ModTime().After(m.lastModTime) {
			// File has not been modified since last check
			return nil
		}

		bytes, err := os.ReadFile(m.cfg.LicenseFile)
		if err != nil {
			if m.cfg.Policy == PolicyDegraded || m.cfg.Policy == PolicyWarnOnly {
				m.transitionToDegraded(err)
				return nil
			}
			return fmt.Errorf("failed to read license file: %w", err)
		}
		rawData = string(bytes)
		modTime = info.ModTime()
	} else {
		rawData = m.cfg.LicenseString
	}

	if rawData == "" {
		if m.cfg.Policy == PolicyDegraded || m.cfg.Policy == PolicyWarnOnly {
			m.transitionToDegraded(ErrLicenseNotFound)
			return nil
		}
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
		if m.cfg.Policy == PolicyDegraded || m.cfg.Policy == PolicyWarnOnly {
			m.transitionToDegraded(err)
			return nil
		}
		return fmt.Errorf("license verification failed: %w", err)
	}

	m.mu.Lock()
	m.lastModTime = modTime
	m.currentLicense = rawData
	m.mu.Unlock()

	if initial {
		m.mu.Lock()
		m.currentClaims = newClaims
		m.isDegraded = false
		m.degradedReason = nil
		m.hasNotifiedExp = false
		m.hasNotifiedGrace = false
		m.lastWarnedDays = -1
		m.mu.Unlock()
	} else {
		m.transitionToRecovered(newClaims, oldClaims)
	}

	return nil
}
