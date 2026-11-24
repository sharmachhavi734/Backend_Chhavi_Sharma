package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Helper function to perform HTTP requests on the test mux
func executeRequest(mux *http.ServeMux, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var bodyBytes []byte
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyBytes = []byte(v)
		case []byte:
			bodyBytes = v
		default:
			bodyBytes, _ = json.Marshal(v)
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// =========================================================================
// Mandatory Test 1: A viewer gets 403 when resolving an alert (Rule R9)
// =========================================================================
func TestViewerGets403WhenResolvingAlert(t *testing.T) {
	store := NewStore()
	handler := NewHandler(store)
	mux := handler.SetupRoutes()

	// 1. Register Acme company with admin
	regResp := executeRequest(mux, "POST", "/register", RegisterRequest{
		OrgName: "Acme",
		Name:    "Asha",
		Email:   "asha@acme.test",
	}, nil)
	if regResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 on register, got %d", regResp.Code)
	}
	var adminUser User
	_ = json.Unmarshal(regResp.Body.Bytes(), &adminUser)

	// 2. Admin adds a viewer user
	userResp := executeRequest(mux, "POST", "/users", CreateUserRequest{
		Name:  "Vik",
		Email: "vik@acme.test",
		Role:  "viewer",
	}, map[string]string{"Authorization": "Bearer " + adminUser.Token})
	if userResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating viewer, got %d", userResp.Code)
	}
	var viewerUser User
	_ = json.Unmarshal(userResp.Body.Bytes(), &viewerUser)

	// 3. Admin adds an app
	appResp := executeRequest(mux, "POST", "/apps", CreateAppRequest{
		Name:     "Acme Pay",
		Platform: "android",
	}, map[string]string{"Authorization": "Bearer " + adminUser.Token})
	if appResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating app, got %d", appResp.Code)
	}
	var app App
	_ = json.Unmarshal(appResp.Body.Bytes(), &app)

	// 4. SDK reports a threat
	alertResp := executeRequest(mux, "POST", "/alerts", ReportAlertRequest{
		DeviceID:   "d1",
		ThreatType: "ROOT_DETECTED",
		Severity:   5,
	}, map[string]string{"X-App-Key": app.AppKey})
	if alertResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 reporting alert, got %d", alertResp.Code)
	}
	var alert Alert
	_ = json.Unmarshal(alertResp.Body.Bytes(), &alert)

	// 5. Viewer attempts to resolve alert -> Must return 403 Forbidden
	resolveResp := executeRequest(mux, "POST", "/alerts/"+alert.ID+"/resolve", nil,
		map[string]string{"Authorization": "Bearer " + viewerUser.Token})

	if resolveResp.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer resolving alert, got %d", resolveResp.Code)
	}

	var errResp ErrorResponse
	_ = json.Unmarshal(resolveResp.Body.Bytes(), &errResp)
	if errResp.Error == "" {
		t.Errorf("expected error message in response body")
	}
}

// =========================================================================
// Mandatory Test 2: A user from another company gets 404 for an alert (Rule R6 & R9)
// =========================================================================
func TestUserFromAnotherCompanyGets404ForAlert(t *testing.T) {
	store := NewStore()
	handler := NewHandler(store)
	mux := handler.SetupRoutes()

	// 1. Register Acme company (admin Asha)
	acmeReg := executeRequest(mux, "POST", "/register", RegisterRequest{
		OrgName: "Acme",
		Name:    "Asha",
		Email:   "asha@acme.test",
	}, nil)
	var acmeAdmin User
	_ = json.Unmarshal(acmeReg.Body.Bytes(), &acmeAdmin)

	// 2. Register Beta company (admin Ravi)
	betaReg := executeRequest(mux, "POST", "/register", RegisterRequest{
		OrgName: "Beta",
		Name:    "Ravi",
		Email:   "ravi@beta.test",
	}, nil)
	var betaAdmin User
	_ = json.Unmarshal(betaReg.Body.Bytes(), &betaAdmin)

	// 3. Acme admin creates an app
	appResp := executeRequest(mux, "POST", "/apps", CreateAppRequest{
		Name:     "Acme Pay",
		Platform: "android",
	}, map[string]string{"Authorization": "Bearer " + acmeAdmin.Token})
	var acmeApp App
	_ = json.Unmarshal(appResp.Body.Bytes(), &acmeApp)

	// 4. SDK creates alert for Acme
	alertResp := executeRequest(mux, "POST", "/alerts", ReportAlertRequest{
		DeviceID:   "d1",
		ThreatType: "ROOT_DETECTED",
		Severity:   5,
	}, map[string]string{"X-App-Key": acmeApp.AppKey})
	var acmeAlert Alert
	_ = json.Unmarshal(alertResp.Body.Bytes(), &acmeAlert)

	// 5. Beta admin attempts to view Acme's alert -> Must return 404 Not Found (Rule R6)
	getResp := executeRequest(mux, "GET", "/alerts/"+acmeAlert.ID, nil,
		map[string]string{"Authorization": "Bearer " + betaAdmin.Token})

	if getResp.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found when Beta admin views Acme's alert, got %d", getResp.Code)
	}

	// 6. Beta admin attempts to resolve Acme's alert -> Must return 404 Not Found (Rule R6)
	resolveResp := executeRequest(mux, "POST", "/alerts/"+acmeAlert.ID+"/resolve", nil,
		map[string]string{"Authorization": "Bearer " + betaAdmin.Token})

	if resolveResp.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found when Beta admin resolves Acme's alert, got %d", resolveResp.Code)
	}
}

// =========================================================================
// Mandatory Test 3: 50 identical alerts sent at the same time give one alert with count 50 (Rule R8 & R9)
// =========================================================================
func TestFiftyIdenticalAlertsConcurrentlyGiveOneAlertWithCountFifty(t *testing.T) {
	store := NewStore()
	handler := NewHandler(store)
	mux := handler.SetupRoutes()

	// 1. Register Acme company
	regResp := executeRequest(mux, "POST", "/register", RegisterRequest{
		OrgName: "Acme",
		Name:    "Asha",
		Email:   "asha@acme.test",
	}, nil)
	var adminUser User
	_ = json.Unmarshal(regResp.Body.Bytes(), &adminUser)

	// 2. Add an app
	appResp := executeRequest(mux, "POST", "/apps", CreateAppRequest{
		Name:     "Acme Pay",
		Platform: "android",
	}, map[string]string{"Authorization": "Bearer " + adminUser.Token})
	var app App
	_ = json.Unmarshal(appResp.Body.Bytes(), &app)

	// 3. Concurrently send 50 identical alerts
	const totalRequests = 50
	var wg sync.WaitGroup
	statusCodes := make([]int, totalRequests)

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			resp := executeRequest(mux, "POST", "/alerts", ReportAlertRequest{
				DeviceID:   "d2",
				ThreatType: "FRIDA_DETECTED",
				Severity:   4,
			}, map[string]string{"X-App-Key": app.AppKey})
			statusCodes[index] = resp.Code
		}(i)
	}

	wg.Wait()

	// Verify all returned either 201 (initial) or 200 (updates)
	for i, code := range statusCodes {
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("request %d returned unexpected status code %d", i, code)
		}
	}

	// 4. Query GET /alerts?status=open
	listResp := executeRequest(mux, "GET", "/alerts?status=open", nil,
		map[string]string{"Authorization": "Bearer " + adminUser.Token})

	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET /alerts, got %d", listResp.Code)
	}

	var alertsResp AlertsResponse
	_ = json.Unmarshal(listResp.Body.Bytes(), &alertsResp)

	if len(alertsResp.Alerts) != 1 {
		t.Fatalf("expected exactly 1 alert, got %d", len(alertsResp.Alerts))
	}

	alert := alertsResp.Alerts[0]
	if alert.Count != 50 {
		t.Errorf("expected alert count to be 50, got %d", alert.Count)
	}
	if alert.DeviceID != "d2" {
		t.Errorf("expected deviceId 'd2', got '%s'", alert.DeviceID)
	}
	if alert.ThreatType != "FRIDA_DETECTED" {
		t.Errorf("expected threatType 'FRIDA_DETECTED', got '%s'", alert.ThreatType)
	}
	if alert.Severity != 4 {
		t.Errorf("expected severity 4, got %d", alert.Severity)
	}
	if alert.Status != "open" {
		t.Errorf("expected status 'open', got '%s'", alert.Status)
	}
}

// =========================================================================
// Comprehensive Test: All 22 Self-Check Scenarios in Exact Order
// =========================================================================
func TestAll22SelfCheckScenarios(t *testing.T) {
	store := NewStore()
	handler := NewHandler(store)
	mux := handler.SetupRoutes()

	var tokenAAdmin string
	var tokenBAdmin string
	var tokenAViewer string
	var appKey string
	var alertID string

	// Step 1: POST /register as no token -> 201, role is "admin", save token as A_ADMIN
	{
		res := executeRequest(mux, "POST", "/register", `{"orgName":"Acme","name":"Asha","email":"asha@acme.test"}`, nil)
		if res.Code != http.StatusCreated {
			t.Fatalf("Step 1 failed: expected 201, got %d", res.Code)
		}
		var u User
		_ = json.Unmarshal(res.Body.Bytes(), &u)
		if u.Role != "admin" {
			t.Fatalf("Step 1 failed: expected role 'admin', got '%s'", u.Role)
		}
		tokenAAdmin = u.Token
	}

	// Step 2: POST /register as no token -> 201, save token as B_ADMIN
	{
		res := executeRequest(mux, "POST", "/register", `{"orgName":"Beta","name":"Ravi","email":"ravi@beta.test"}`, nil)
		if res.Code != http.StatusCreated {
			t.Fatalf("Step 2 failed: expected 201, got %d", res.Code)
		}
		var u User
		_ = json.Unmarshal(res.Body.Bytes(), &u)
		tokenBAdmin = u.Token
	}

	// Step 3: POST /register as no token with bad email -> 400
	{
		res := executeRequest(mux, "POST", "/register", `{"orgName":"Gamma","name":"Gita","email":"not-an-email"}`, nil)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("Step 3 failed: expected 400, got %d", res.Code)
		}
	}

	// Step 4: Acme admin adds a viewer -> 201, role is "viewer", save token as A_VIEWER
	{
		res := executeRequest(mux, "POST", "/users", `{"name":"Vik","email":"vik@acme.test","role":"viewer"}`,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusCreated {
			t.Fatalf("Step 4 failed: expected 201, got %d", res.Code)
		}
		var u User
		_ = json.Unmarshal(res.Body.Bytes(), &u)
		if u.Role != "viewer" {
			t.Fatalf("Step 4 failed: expected role 'viewer', got '%s'", u.Role)
		}
		tokenAViewer = u.Token
	}

	// Step 5: Viewer tries to add a user -> 403
	{
		res := executeRequest(mux, "POST", "/users", `{"name":"Xia","email":"xia@acme.test","role":"admin"}`,
			map[string]string{"Authorization": "Bearer " + tokenAViewer})
		if res.Code != http.StatusForbidden {
			t.Fatalf("Step 5 failed: expected 403, got %d", res.Code)
		}
	}

	// Step 6: Add a user with no token -> 401
	{
		res := executeRequest(mux, "POST", "/users", `{"name":"Xia","email":"xia@acme.test","role":"admin"}`, nil)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("Step 6 failed: expected 401, got %d", res.Code)
		}
	}

	// Step 7: Acme admin adds an app -> 201, save appKey as APP_KEY
	{
		res := executeRequest(mux, "POST", "/apps", `{"name":"Acme Pay","platform":"android"}`,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusCreated {
			t.Fatalf("Step 7 failed: expected 201, got %d", res.Code)
		}
		var a App
		_ = json.Unmarshal(res.Body.Bytes(), &a)
		if a.AppKey == "" {
			t.Fatalf("Step 7 failed: expected non-empty appKey")
		}
		appKey = a.AppKey
	}

	// Step 8: Add an app with a wrong platform -> 400
	{
		res := executeRequest(mux, "POST", "/apps", `{"name":"Acme Web","platform":"windows"}`,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusBadRequest {
			t.Fatalf("Step 8 failed: expected 400, got %d", res.Code)
		}
	}

	// Step 9: SDK reports a threat -> 201, count is 1, status is "open", save id as ALERT_ID
	{
		res := executeRequest(mux, "POST", "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`,
			map[string]string{"X-App-Key": appKey})
		if res.Code != http.StatusCreated {
			t.Fatalf("Step 9 failed: expected 201, got %d", res.Code)
		}
		var al Alert
		_ = json.Unmarshal(res.Body.Bytes(), &al)
		if al.Count != 1 || al.Status != "open" {
			t.Fatalf("Step 9 failed: expected count 1 and status 'open', got count %d, status '%s'", al.Count, al.Status)
		}
		alertID = al.ID
	}

	// Step 10: Same device, same threat again -> 200, count is 2, same id as ALERT_ID
	{
		res := executeRequest(mux, "POST", "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`,
			map[string]string{"X-App-Key": appKey})
		if res.Code != http.StatusOK {
			t.Fatalf("Step 10 failed: expected 200, got %d", res.Code)
		}
		var al Alert
		_ = json.Unmarshal(res.Body.Bytes(), &al)
		if al.Count != 2 || al.ID != alertID {
			t.Fatalf("Step 10 failed: expected count 2 and same id %s, got count %d, id %s", alertID, al.Count, al.ID)
		}
	}

	// Step 11: Severity out of range -> 400
	{
		res := executeRequest(mux, "POST", "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":9}`,
			map[string]string{"X-App-Key": appKey})
		if res.Code != http.StatusBadRequest {
			t.Fatalf("Step 11 failed: expected 400, got %d", res.Code)
		}
	}

	// Step 12: Wrong app key -> 401
	{
		res := executeRequest(mux, "POST", "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`,
			map[string]string{"X-App-Key": "wrong-key"})
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("Step 12 failed: expected 401, got %d", res.Code)
		}
	}

	// Step 13: Acme viewer lists alerts -> 200, 1 alert in the list
	{
		res := executeRequest(mux, "GET", "/alerts", nil,
			map[string]string{"Authorization": "Bearer " + tokenAViewer})
		if res.Code != http.StatusOK {
			t.Fatalf("Step 13 failed: expected 200, got %d", res.Code)
		}
		var resp AlertsResponse
		_ = json.Unmarshal(res.Body.Bytes(), &resp)
		if len(resp.Alerts) != 1 {
			t.Fatalf("Step 13 failed: expected 1 alert in list, got %d", len(resp.Alerts))
		}
	}

	// Step 14: Beta admin lists alerts -> 200, 0 alerts in the list
	{
		res := executeRequest(mux, "GET", "/alerts", nil,
			map[string]string{"Authorization": "Bearer " + tokenBAdmin})
		if res.Code != http.StatusOK {
			t.Fatalf("Step 14 failed: expected 200, got %d", res.Code)
		}
		var resp AlertsResponse
		_ = json.Unmarshal(res.Body.Bytes(), &resp)
		if resp.Alerts == nil || len(resp.Alerts) != 0 {
			t.Fatalf("Step 14 failed: expected 0 alerts and non-null list, got %v", resp.Alerts)
		}
		// Confirm json representation is literally "[]"
		if !bytes.Contains(res.Body.Bytes(), []byte(`"alerts":[]`)) && !bytes.Contains(res.Body.Bytes(), []byte(`"alerts": []`)) {
			t.Fatalf("Step 14 failed: alerts list must be empty [] in JSON, got %s", res.Body.String())
		}
	}

	// Step 15: Beta admin opens Acme's alert -> 404
	{
		res := executeRequest(mux, "GET", "/alerts/"+alertID, nil,
			map[string]string{"Authorization": "Bearer " + tokenBAdmin})
		if res.Code != http.StatusNotFound {
			t.Fatalf("Step 15 failed: expected 404, got %d", res.Code)
		}
	}

	// Step 16: Acme viewer resolves the alert -> 403
	{
		res := executeRequest(mux, "POST", "/alerts/"+alertID+"/resolve", nil,
			map[string]string{"Authorization": "Bearer " + tokenAViewer})
		if res.Code != http.StatusForbidden {
			t.Fatalf("Step 16 failed: expected 403, got %d", res.Code)
		}
	}

	// Step 17: Beta admin resolves Acme's alert -> 404
	{
		res := executeRequest(mux, "POST", "/alerts/"+alertID+"/resolve", nil,
			map[string]string{"Authorization": "Bearer " + tokenBAdmin})
		if res.Code != http.StatusNotFound {
			t.Fatalf("Step 17 failed: expected 404, got %d", res.Code)
		}
	}

	// Step 18: Acme admin resolves the alert -> 200, status is "resolved"
	{
		res := executeRequest(mux, "POST", "/alerts/"+alertID+"/resolve", nil,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusOK {
			t.Fatalf("Step 18 failed: expected 200, got %d", res.Code)
		}
		var al Alert
		_ = json.Unmarshal(res.Body.Bytes(), &al)
		if al.Status != "resolved" {
			t.Fatalf("Step 18 failed: expected status 'resolved', got '%s'", al.Status)
		}
	}

	// Step 19: Resolve it again -> 409
	{
		res := executeRequest(mux, "POST", "/alerts/"+alertID+"/resolve", nil,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusConflict {
			t.Fatalf("Step 19 failed: expected 409, got %d", res.Code)
		}
	}

	// Step 20: Same threat after it was resolved -> 201, count is 1, a new id, not ALERT_ID
	{
		res := executeRequest(mux, "POST", "/alerts", `{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`,
			map[string]string{"X-App-Key": appKey})
		if res.Code != http.StatusCreated {
			t.Fatalf("Step 20 failed: expected 201, got %d", res.Code)
		}
		var al Alert
		_ = json.Unmarshal(res.Body.Bytes(), &al)
		if al.Count != 1 || al.ID == alertID {
			t.Fatalf("Step 20 failed: expected count 1 and new id != %s, got count %d, id %s", alertID, al.Count, al.ID)
		}
	}

	// Step 21: List only open alerts -> 200, 1 alert in the list
	{
		res := executeRequest(mux, "GET", "/alerts?status=open", nil,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusOK {
			t.Fatalf("Step 21 failed: expected 200, got %d", res.Code)
		}
		var resp AlertsResponse
		_ = json.Unmarshal(res.Body.Bytes(), &resp)
		if len(resp.Alerts) != 1 {
			t.Fatalf("Step 21 failed: expected 1 open alert, got %d", len(resp.Alerts))
		}
	}

	// Step 22: 50 identical reports sent at the same time
	{
		const count50 = 50
		var wg sync.WaitGroup
		responses := make([]int, count50)

		for i := 0; i < count50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				r := executeRequest(mux, "POST", "/alerts",
					`{"deviceId":"d2","threatType":"FRIDA_DETECTED","severity":4}`,
					map[string]string{"X-App-Key": appKey})
				responses[idx] = r.Code
			}(i)
		}
		wg.Wait()

		for i, c := range responses {
			if c != http.StatusOK && c != http.StatusCreated {
				t.Fatalf("Step 22 concurrent request %d failed with status %d", i, c)
			}
		}

		// Then GET /alerts?status=open shows one alert for d2 with count 50
		res := executeRequest(mux, "GET", "/alerts?status=open", nil,
			map[string]string{"Authorization": "Bearer " + tokenAAdmin})
		if res.Code != http.StatusOK {
			t.Fatalf("Step 22 GET failed: expected 200, got %d", res.Code)
		}
		var resp AlertsResponse
		_ = json.Unmarshal(res.Body.Bytes(), &resp)

		var foundD2 *Alert
		for _, a := range resp.Alerts {
			if a.DeviceID == "d2" && a.ThreatType == "FRIDA_DETECTED" {
				foundD2 = a
				break
			}
		}

		if foundD2 == nil {
			t.Fatalf("Step 22 failed: alert for d2 not found in open alerts")
		}
		if foundD2.Count != 50 {
			t.Fatalf("Step 22 failed: expected alert for d2 to have count 50, got %d", foundD2.Count)
		}
	}

	fmt.Println("All 22 self-check scenarios passed successfully!")
}
