package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"grantsupport/pkg/service"
)

func TestGrantSupportServiceValidation(t *testing.T) {
	svc := service.NewGrantSupportService(nil, nil, nil)

	t.Run("CreateSupportGrant fails with nil repository", func(t *testing.T) {
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 60)
		if err == nil {
			t.Errorf("Expected error when supportGrantRepo is nil")
		}
	})

	t.Run("CreateSupportGrant fails with invalid duration (0 minutes)", func(t *testing.T) {
		svc := service.NewGrantSupportService(nil, nil, nil)
		_, err := svc.CreateSupportGrant(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), 0)
		if err == nil {
			t.Errorf("Expected error for 0 minutes duration")
		}
	})

	t.Run("SupportLogin fails with malformed token", func(t *testing.T) {
		_, _, err := svc.SupportLogin(context.Background(), "invalid-token-without-underscore", uuid.Must(uuid.NewV7()))
		if err == nil {
			t.Errorf("Expected error for malformed token format")
		}
	})
}
