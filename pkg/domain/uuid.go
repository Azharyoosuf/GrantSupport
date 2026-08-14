package domain

import "github.com/google/uuid"

// NewUUID generates a cryptographically secure, time-ordered UUIDv7 conforming to RFC 9562 for application entities.
func NewUUID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

// NewUUIDString generates a cryptographically secure, time-ordered UUIDv7 string conforming to RFC 9562.
func NewUUIDString() string {
	return uuid.Must(uuid.NewV7()).String()
}
