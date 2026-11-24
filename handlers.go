package main

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Handler holds the application routes and shared in-memory store.
type Handler struct {
	store *Store
}

// NewHandler creates a new Handler with the given Store.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// SetupRoutes registers all API endpoints using Go 1.22+ ServeMux routing patterns.
func (h *Handler) SetupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// 1. POST /register (Public)
	mux.HandleFunc("POST /register", h.handleRegister)

	// 2. POST /users (Admin only)
	mux.HandleFunc("POST /users", h.handleCreateUser)

	// 3. POST /apps (Admin only)
	mux.HandleFunc("POST /apps", h.handleCreateApp)

	// 4. POST /alerts (SDK with X-App-Key)
	mux.HandleFunc("POST /alerts", h.handleReportAlert)

	// 5. GET /alerts (Admin or Viewer)
	mux.HandleFunc("GET /alerts", h.handleListAlerts)

	// 6. GET /alerts/{id} (Admin or Viewer)
	mux.HandleFunc("GET /alerts/{id}", h.handleGetAlertByID)

	// 7. POST /alerts/{id}/resolve (Admin only)
	mux.HandleFunc("POST /alerts/{id}/resolve", h.handleResolveAlert)

	// Bonus: GET /summary (Admin or Viewer)
	mux.HandleFunc("GET /summary", h.handleSummary)

	return mux
}

// 1. POST /register: Anyone can call. Creates a company and its first user, who is an admin.
func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateRegisterInput(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.store.RegisterCompanyAndAdmin(req.OrgName, req.Name, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to register company")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// 2. POST /users: Adds a user to the caller's company. Role is "admin" or "viewer".
// Follows Rule R5: 401 (Auth) -> 403 (Role) -> 400 (Input) -> 201 (Created).
func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check who is calling (401)
	user, ok := authenticateUser(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid token")
		return
	}

	// Step 2: Check their role (403)
	if !requireAdmin(user) {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return
	}

	// Step 3: Check the input (400)
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateCreateUserInput(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step 4: Execute operation
	newUser, err := h.store.AddUser(user.OrgID, req.Name, req.Email, req.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, newUser)
}

// 3. POST /apps: Adds an app to the caller's company. Platform is "android" or "ios".
// Follows Rule R5: 401 (Auth) -> 403 (Role) -> 400 (Input) -> 201 (Created).
func (h *Handler) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check who is calling (401)
	user, ok := authenticateUser(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid token")
		return
	}

	// Step 2: Check their role (403)
	if !requireAdmin(user) {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return
	}

	// Step 3: Check the input (400)
	var req CreateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateCreateAppInput(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step 4: Execute operation
	app, err := h.store.AddApp(user.OrgID, req.Name, req.Platform)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create app")
		return
	}

	writeJSON(w, http.StatusCreated, app)
}

// 4. POST /alerts: Reports a threat via the SDK.
// Follows Rule R5: 401 (Auth) -> 400 (Input) -> 201 / 200.
func (h *Handler) handleReportAlert(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check who is calling (401)
	app, ok := authenticateSDK(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid app key")
		return
	}

	// Step 2: Check the input (400)
	var req ReportAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateReportAlertInput(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step 3: Record alert (handles atomic repeat deduplication)
	alert, isNew, err := h.store.RecordAlert(app.AppKey, req.DeviceID, req.ThreatType, req.Severity)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record alert")
		return
	}

	if isNew {
		writeJSON(w, http.StatusCreated, alert)
	} else {
		writeJSON(w, http.StatusOK, alert)
	}
}

// 5. GET /alerts: Lists alerts belonging to the caller's company only, newest lastSeen first.
// Optional filter: ?status=open or ?status=resolved.
// Follows Rule R5: 401 (Auth) -> 403 (Role) -> 400 (Input) -> 200.
func (h *Handler) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check who is calling (401)
	user, ok := authenticateUser(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid token")
		return
	}

	// Step 2: Role check (both admin and viewer allowed)

	// Step 3: Check the input (400)
	statusFilter := r.URL.Query().Get("status")
	if err := validateStatusFilter(statusFilter); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step 4: Retrieve alerts for user's company
	alerts := h.store.GetAlerts(user.OrgID, statusFilter)

	// Bonus: Optional pagination parameters ?limit= and ?offset=
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	offset := 0
	limit := len(alerts)

	if offsetStr != "" {
		parsedOffset, err := strconv.Atoi(offsetStr)
		if err != nil || parsedOffset < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = parsedOffset
	}

	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit < 0 {
			writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		limit = parsedLimit
	}

	if offset > len(alerts) {
		alerts = make([]*Alert, 0)
	} else {
		end := offset + limit
		if end > len(alerts) {
			end = len(alerts)
		}
		alerts = alerts[offset:end]
	}

	writeJSON(w, http.StatusOK, AlertsResponse{Alerts: alerts})
}

// 6. GET /alerts/{id}: Returns one alert by ID for caller's company.
// Follows Rule R5: 401 (Auth) -> 403 (Role) -> 400 (Input) -> 404 (Tenancy/Existence) -> 200.
func (h *Handler) handleGetAlertByID(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check who is calling (401)
	user, ok := authenticateUser(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid token")
		return
	}

	// Step 2: Role check (both admin and viewer allowed)

	// Step 3: Check input (400)
	alertID := r.PathValue("id")
	if alertID == "" {
		writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}

	// Step 4: Check existence and company isolation (404)
	alert, ok := h.store.GetAlertByID(user.OrgID, alertID)
	if !ok {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

// 7. POST /alerts/{id}/resolve: Resolves an alert for the caller's company.
// Follows Rule R5: 401 (Auth) -> 403 (Role) -> 400 (Input) -> 404 (Tenancy) -> 409 (Conflict) -> 200.
func (h *Handler) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check who is calling (401)
	user, ok := authenticateUser(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid token")
		return
	}

	// Step 2: Check their role (403) - only admin can resolve alerts
	if !requireAdmin(user) {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return
	}

	// Step 3: Check input (400)
	alertID := r.PathValue("id")
	if alertID == "" {
		writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}

	// Step 4 & 5: Check existence (404) and conflict if already resolved (409)
	alert, err := h.store.ResolveAlert(user.OrgID, alertID, user.UserID)
	if err != nil {
		if err == ErrNotFound {
			writeError(w, http.StatusNotFound, "alert not found")
			return
		}
		if err == ErrAlreadyResolved {
			writeError(w, http.StatusConflict, "the alert is already resolved")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to resolve alert")
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

// Bonus: GET /summary: returns count of open alerts for each severity for caller's company.
func (h *Handler) handleSummary(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticateUser(r, h.store)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid token")
		return
	}

	alerts := h.store.GetAlerts(user.OrgID, "open")
	summary := map[string]int{
		"severity_1": 0,
		"severity_2": 0,
		"severity_3": 0,
		"severity_4": 0,
		"severity_5": 0,
	}

	for _, a := range alerts {
		switch a.Severity {
		case 1:
			summary["severity_1"]++
		case 2:
			summary["severity_2"]++
		case 3:
			summary["severity_3"]++
		case 4:
			summary["severity_4"]++
		case 5:
			summary["severity_5"]++
		}
	}

	writeJSON(w, http.StatusOK, summary)
}
