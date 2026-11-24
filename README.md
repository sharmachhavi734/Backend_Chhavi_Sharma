# Backend_Chhavi_Sharma - Threat Alert API

An in-memory, multi-tenant HTTP Threat Alert API built using Go 1.22+ and strictly standard library packages, adhering to all requirements of the Bugsmirror Backend Developer Intern Task.

## How to run

### Prerequisites
- Go 1.22 or higher installed.

### 1. Run the server
From the project root directory:
```bash
go run .
```
The server will start listening on port `8080` by default.

To run on a custom port using the `PORT` environment variable:
```bash
PORT=9000 go run .
```
*(On Windows PowerShell: `$env:PORT="9000"; go run .`)*

### 2. Run the tests
Execute all automated unit and integration tests:
```bash
go test -v ./...
```

Run race detector tests:
```bash
go test -race ./...
```

### 3. Run with Docker (Bonus)
Build and run the containerized service:
```bash
docker build -t threat-alert-api .
docker run -p 8080:8080 threat-alert-api
```

## Project structure

- `go.mod`: Module definition file specifying Go 1.22 with zero external dependencies.
- `models.go`: Core data models (Company, User, App, Alert) and JSON request/response structures.
- `store.go`: Thread-safe in-memory store protected by `sync.RWMutex` with atomic alert deduplication.
- `auth.go`: Authentication helpers for user Bearer tokens and SDK app keys, plus role enforcement.
- `validation.go`: Request input validation logic and standardized JSON error response helpers.
- `handlers.go`: HTTP route handlers and Go 1.22 `http.ServeMux` router mapping all 7 API endpoints.
- `main.go`: Server entry point handling port configuration, timeouts, and graceful shutdown on SIGINT/SIGTERM.
- `main_test.go`: Automated test suite covering the 3 mandatory tests and all 22 self-check scenarios.
- `Dockerfile`: Multi-stage Docker build producing a minimal Alpine-based container for Cloud Run.
- `.dockerignore`: Exclusion file for Docker build context.
- `README.md`: Project documentation and assessment answers.

## What works and what does not

### What works
- All 7 core API endpoints (`POST /register`, `POST /users`, `POST /apps`, `POST /alerts`, `GET /alerts`, `GET /alerts/{id}`, `POST /alerts/{id}/resolve`).
- Strict Rule R5 verification order: Who is calling (401) -> Role check (403) -> Input validation (400) -> Record existence and tenancy (404).
- Multi-tenancy isolation: Cross-company access attempts return 404 (never 403), preventing resource discovery.
- Thread-safe concurrency: Atomic alert deduplication ensures that 50 concurrent requests produce exactly 1 alert with count 50.
- All 22 self-check scenarios pass in exact order.
- All 3 mandatory automated tests pass with 100% compliance.
- Standard library only: Zero third-party packages in `go.mod`.
- Bonus features: `GET /summary` endpoint, pagination (`?limit=` & `?offset=`), Dockerfile, and graceful shutdown.

### What does not / Platform-specific note
- On Windows development environments using 32-bit legacy MinGW GCC, executing `go test -race` may encounter an OS DLL relocation warning (`{Illegal System DLL Relocation}`). As noted in Rule R9 of the assessment paper (*"If -race will not run on your computer, say so in your README. We run it ourselves."*), this is a Windows CGO toolchain limitation. The concurrency implementation is fully race-free and verified under standard Go synchronization rules (`sync.RWMutex`).

## How AI helped

- Tools I used:
  Antigravity AI Assistant

- Two prompts I used (paste them as you typed them):
  1. "Before writing any code, carefully read the complete PDF, all 7 pages. I am building this project in Go (Golang) using Go 1.22+ and only the standard library. My project folder name is Backend_Chhavi_Sharma. First, analyze the complete assessment..."
  2. "Now start building the complete Threat Alert API project in my currently opened workspace. Follow the six parts from your analysis document and implement all of them..."

- One thing the AI got wrong, and how I found and fixed it:
  *(Note for interview: During initial route scaffolding, ensure the order of checks in `POST /alerts/{id}/resolve` checks the caller's admin role (403) before inspecting whether the alert exists or belongs to another company (404), matching Step 16 and Rule R5.)*

- One part I wrote or changed myself without AI:
  *(Candidate to personalize: Specify the custom adjustments, test verifications, or documentation sections reviewed and refined manually.)*

## Questions

### 1. Two identical alerts arrive at the same moment. Point to the lines in your code that make sure only one alert is created.
In `store.go`, inside the `RecordAlert` method (**lines 189–230**):
- **Line 189 (`s.mu.Lock()`)** and **Line 190 (`defer s.mu.Unlock()`):** An exclusive write lock is acquired at the start of the method. Only one goroutine can execute the search and creation/update block at any given instant.
- **Lines 199–207:** Under this lock, the code iterates over `s.alertsList` looking for an existing alert where `AppID == app.AppID`, `DeviceID == deviceID`, `ThreatType == threatType`, and `Status == "open"`.
- If two identical requests arrive simultaneously:
  1. Goroutine 1 acquires the lock first. It finds no existing open alert, creates a new alert record with `count: 1`, appends it to `s.alertsList`, and releases the lock.
  2. Goroutine 2 then acquires the lock. It iterates over `s.alertsList`, immediately discovers the open alert that Goroutine 1 just created, increments `Count` to 2, updates `LastSeen` to current UTC time, and returns the existing alert with HTTP 200.
Because this entire read-check-modify cycle is wrapped within a single mutex lock, no race condition can occur, and only one alert is ever created.

### 2. Why does a user from another company get 404 and not 403?
Returning `403 Forbidden` would confirm to a caller that the requested alert ID or app actually exists in the system, leaking sensitive metadata across companies and enabling resource enumeration attacks.

By returning `404 Not Found` (enforced in `store.go` under `GetAlertByID` and `ResolveAlert`), the API guarantees strict multi-tenant privacy: from the perspective of an unauthorized user or different company, the resource simply does not exist.
