package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrAlreadyResolved = errors.New("the alert is already resolved")
	ErrInvalidAppKey   = errors.New("invalid app key")
)

// Store provides thread-safe in-memory storage for companies, users, apps, and alerts.
type Store struct {
	mu sync.RWMutex

	companies    map[string]*Company
	users        map[string]*User
	usersByToken map[string]*User
	apps         map[string]*App
	appsByKey    map[string]*App
	alerts       map[string]*Alert
	alertsList   []*Alert

	orgCounter   int
	userCounter  int
	appCounter   int
	alertCounter int
}

// NewStore initializes a new in-memory store.
func NewStore() *Store {
	return &Store{
		companies:    make(map[string]*Company),
		users:        make(map[string]*User),
		usersByToken: make(map[string]*User),
		apps:         make(map[string]*App),
		appsByKey:    make(map[string]*App),
		alerts:       make(map[string]*Alert),
		alertsList:   make([]*Alert, 0),
	}
}

// generateRandomHex generates at least 16 random bytes and returns a hex string (Rule R7).
func generateRandomHex(byteCount int) (string, error) {
	if byteCount < 16 {
		byteCount = 16
	}
	bytes := make([]byte, byteCount)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// RegisterCompanyAndAdmin creates a new company and its first admin user atomically.
func (s *Store) RegisterCompanyAndAdmin(orgName, adminName, email string) (*User, error) {
	token, err := generateRandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.orgCounter++
	orgID := fmt.Sprintf("org_%d", s.orgCounter)

	s.userCounter++
	userID := fmt.Sprintf("usr_%d", s.userCounter)

	company := &Company{
		OrgID: orgID,
		Name:  orgName,
	}
	s.companies[orgID] = company

	user := &User{
		UserID: userID,
		OrgID:  orgID,
		Name:   adminName,
		Email:  email,
		Role:   "admin",
		Token:  token,
	}
	s.users[userID] = user
	s.usersByToken[token] = user

	return user, nil
}

// AddUser adds a user to the specified organization.
func (s *Store) AddUser(orgID, name, email, role string) (*User, error) {
	token, err := generateRandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.companies[orgID]; !ok {
		return nil, ErrNotFound
	}

	s.userCounter++
	userID := fmt.Sprintf("usr_%d", s.userCounter)

	user := &User{
		UserID: userID,
		OrgID:  orgID,
		Name:   name,
		Email:  email,
		Role:   role,
		Token:  token,
	}
	s.users[userID] = user
	s.usersByToken[token] = user

	return user, nil
}

// AddApp adds an application to the specified organization.
func (s *Store) AddApp(orgID, name, platform string) (*App, error) {
	appKey, err := generateRandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate appKey: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.companies[orgID]; !ok {
		return nil, ErrNotFound
	}

	s.appCounter++
	appID := fmt.Sprintf("app_%d", s.appCounter)

	app := &App{
		AppID:    appID,
		OrgID:    orgID,
		Name:     name,
		Platform: platform,
		AppKey:   appKey,
	}
	s.apps[appID] = app
	s.appsByKey[appKey] = app

	return app, nil
}

// GetUserByToken looks up a user by their secret token.
func (s *Store) GetUserByToken(token string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.usersByToken[token]
	if !ok {
		return nil, false
	}
	return user, true
}

// GetAppByKey looks up an app by its secret appKey.
func (s *Store) GetAppByKey(appKey string) (*App, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	app, ok := s.appsByKey[appKey]
	if !ok {
		return nil, false
	}
	return app, true
}

// RecordAlert handles threat reporting from the SDK with atomic repeat deduplication.
// If an open alert exists for the same app, deviceId and threatType:
// increments count, updates lastSeen to now (UTC), preserves initial severity, and returns (alert, false, nil).
// Otherwise, creates a new alert with count 1, and returns (alert, true, nil).
func (s *Store) RecordAlert(appKey, deviceID, threatType string, severity int) (*Alert, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	app, ok := s.appsByKey[appKey]
	if !ok {
		return nil, false, ErrInvalidAppKey
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Check for an existing open alert for same app, deviceId, and threatType
	for _, a := range s.alertsList {
		if a.AppID == app.AppID && a.DeviceID == deviceID && a.ThreatType == threatType && a.Status == "open" {
			// Repeat alert: update count and lastSeen, keep original severity
			a.Count++
			a.LastSeen = now
			return a, false, nil
		}
	}

	// No matching open alert: create a new alert
	s.alertCounter++
	alertID := fmt.Sprintf("alr_%d", s.alertCounter)

	newAlert := &Alert{
		ID:         alertID,
		AppID:      app.AppID,
		DeviceID:   deviceID,
		ThreatType: threatType,
		Severity:   severity,
		Count:      1,
		Status:     "open",
		FirstSeen:  now,
		LastSeen:   now,
		ResolvedBy: "",
	}

	s.alerts[alertID] = newAlert
	s.alertsList = append(s.alertsList, newAlert)

	return newAlert, true, nil
}

// GetAlerts returns alerts belonging to the caller's company only, newest lastSeen first.
// If statusFilter is provided ("open" or "resolved"), only alerts with that status are returned.
// Always returns a non-nil slice ([]).
func (s *Store) GetAlerts(orgID, statusFilter string) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find all apps belonging to this company
	companyAppIDs := make(map[string]bool)
	for _, app := range s.apps {
		if app.OrgID == orgID {
			companyAppIDs[app.AppID] = true
		}
	}

	result := make([]*Alert, 0)
	for _, alert := range s.alertsList {
		if !companyAppIDs[alert.AppID] {
			continue
		}
		if statusFilter != "" && alert.Status != statusFilter {
			continue
		}
		result = append(result, alert)
	}

	// Sort newest lastSeen first. If lastSeen is identical, sort by ID descending.
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].LastSeen != result[j].LastSeen {
			return result[i].LastSeen > result[j].LastSeen
		}
		return result[i].ID > result[j].ID
	})

	return result
}

// GetAlertByID returns an alert by its ID, ensuring company isolation (Rule R6).
// Returns (nil, false) if the alert does not exist or belongs to another company.
func (s *Store) GetAlertByID(orgID, alertID string) (*Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alert, ok := s.alerts[alertID]
	if !ok {
		return nil, false
	}

	app, ok := s.apps[alert.AppID]
	if !ok || app.OrgID != orgID {
		// Alert belongs to another company or unknown app -> return not found (Rule R6)
		return nil, false
	}

	return alert, true
}

// ResolveAlert resolves an alert for the caller's company.
// Returns ErrNotFound (404) if alert doesn't exist or belongs to another company.
// Returns ErrAlreadyResolved (409) if the alert is already resolved.
func (s *Store) ResolveAlert(orgID, alertID, adminUserID string) (*Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[alertID]
	if !ok {
		return nil, ErrNotFound
	}

	app, ok := s.apps[alert.AppID]
	if !ok || app.OrgID != orgID {
		// Multi-tenancy check: return 404 so caller cannot discover another company's alert
		return nil, ErrNotFound
	}

	if alert.Status == "resolved" {
		return nil, ErrAlreadyResolved
	}

	alert.Status = "resolved"
	alert.ResolvedBy = adminUserID

	return alert, nil
}
