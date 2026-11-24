# Multi-stage Dockerfile for Cloud Run
# Stage 1: Build the Go binary using official Golang alpine image
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency manifests and source files
COPY go.mod ./
COPY *.go ./

# Compile statically linked binary with compiler optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o threat-alert-api .

# Stage 2: Create minimal final runtime container
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/threat-alert-api .

# Expose default port (Cloud Run sets PORT env var)
EXPOSE 8080

CMD ["./threat-alert-api"]
