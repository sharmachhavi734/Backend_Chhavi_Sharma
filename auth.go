package main

import (
	"net/http"
	"strings"
)

// authenticateUser extracts and validates the Bearer token from the Authorization header.
// Returns the authenticated User or false if missing/invalid (Rule R4: 401).
func authenticateUser(r *http.Request, store *Store) (*User, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, false
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return nil, false
	}

	user, ok := store.GetUserByToken(token)
	if !ok {
		return nil, false
	}

	return user, true
}

// authenticateSDK extracts and validates the X-App-Key header.
// Returns the registered App or false if missing/invalid (Rule R4: 401).
func authenticateSDK(r *http.Request, store *Store) (*App, bool) {
	appKey := strings.TrimSpace(r.Header.Get("X-App-Key"))
	if appKey == "" {
		return nil, false
	}

	app, ok := store.GetAppByKey(appKey)
	if !ok {
		return nil, false
	}

	return app, true
}

// requireAdmin checks if the user has admin role (Rule R4: 403).
func requireAdmin(user *User) bool {
	return user != nil && user.Role == "admin"
}
