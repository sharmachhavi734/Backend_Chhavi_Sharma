package main

// Company represents a customer organization created by /register.
type Company struct {
	OrgID string `json:"orgId"`
	Name  string `json:"name"`
}

// User represents a company user with role admin or viewer.
type User struct {
	UserID string `json:"userId"`
	OrgID  string `json:"orgId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Token  string `json:"token"`
}

// App represents an application belonging to a company.
// Note: JSON response contains appId, name, platform, appKey (orgId is internal).
type App struct {
	AppID    string `json:"appId"`
	OrgID    string `json:"-"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	AppKey   string `json:"appKey"`
}

// Alert represents a threat alert reported by the mobile SDK.
type Alert struct {
	ID         string `json:"id"`
	AppID      string `json:"appId"`
	DeviceID   string `json:"deviceId"`
	ThreatType string `json:"threatType"`
	Severity   int    `json:"severity"`
	Count      int    `json:"count"`
	Status     string `json:"status"`
	FirstSeen  string `json:"firstSeen"`
	LastSeen   string `json:"lastSeen"`
	ResolvedBy string `json:"resolvedBy"`
}

// AlertsResponse is the wrapper format for GET /alerts.
type AlertsResponse struct {
	Alerts []*Alert `json:"alerts"`
}

// ErrorResponse represents any API failure response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Request payloads

type RegisterRequest struct {
	OrgName string `json:"orgName"`
	Name    string `json:"name"`
	Email   string `json:"email"`
}

type CreateUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type CreateAppRequest struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

type ReportAlertRequest struct {
	DeviceID   string `json:"deviceId"`
	ThreatType string `json:"threatType"`
	Severity   int    `json:"severity"`
}
