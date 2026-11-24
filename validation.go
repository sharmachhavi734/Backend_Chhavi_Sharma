package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// writeJSON writes a JSON response with the given status code and sets Content-Type header.
func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// writeError writes a standardized error response in the format {"error": "short message"}.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{Error: message})
}

// validateNameAndEmail ensures name is non-empty and email contains '@'.
func validateNameAndEmail(name, email string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name must not be empty")
	}
	if strings.TrimSpace(email) == "" || !strings.Contains(email, "@") {
		return errors.New("email must not be empty and must contain @")
	}
	return nil
}

// validateRegisterInput validates the fields for POST /register.
func validateRegisterInput(req RegisterRequest) error {
	if strings.TrimSpace(req.OrgName) == "" {
		return errors.New("orgName must not be empty")
	}
	return validateNameAndEmail(req.Name, req.Email)
}

// validateCreateUserInput validates the fields for POST /users.
func validateCreateUserInput(req CreateUserRequest) error {
	if err := validateNameAndEmail(req.Name, req.Email); err != nil {
		return err
	}
	if req.Role != "admin" && req.Role != "viewer" {
		return errors.New("role must be admin or viewer")
	}
	return nil
}

// validateCreateAppInput validates the fields for POST /apps.
func validateCreateAppInput(req CreateAppRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name must not be empty")
	}
	if req.Platform != "android" && req.Platform != "ios" {
		return errors.New("platform must be android or ios")
	}
	return nil
}

// validateReportAlertInput validates the fields for POST /alerts.
func validateReportAlertInput(req ReportAlertRequest) error {
	if strings.TrimSpace(req.DeviceID) == "" {
		return errors.New("deviceId must not be empty")
	}
	if strings.TrimSpace(req.ThreatType) == "" {
		return errors.New("threatType must not be empty")
	}
	if req.Severity < 1 || req.Severity > 5 {
		return errors.New("severity must be a whole number from 1 to 5")
	}
	return nil
}

// validateStatusFilter validates the optional ?status= query parameter on GET /alerts.
func validateStatusFilter(status string) error {
	if status == "" {
		return nil
	}
	if status != "open" && status != "resolved" {
		return errors.New("status must be open or resolved")
	}
	return nil
}
