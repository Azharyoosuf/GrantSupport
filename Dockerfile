# Multi-stage Dockerfile for GrantSupport Standalone Engine with native cross-compilation
# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s" -o /app/grantsupport cmd/server/main.go

# Minimal distroless runtime image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

COPY --from=builder /app/grantsupport /grantsupport
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/grantsupport"]
