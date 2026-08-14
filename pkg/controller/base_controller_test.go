package controller_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"grantsupport/pkg/controller"
)

type SampleTestDTO struct {
	Name  string `json:"name" validate:"required"`
	Count int    `json:"count" validate:"gte=1"`
}

func TestDecodeAndValidate_ValidPayload(t *testing.T) {
	body := []byte(`{"name":"test_grant","count":5}`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))

	dto, err := controller.DecodeAndValidate[SampleTestDTO](req)
	if err != nil {
		t.Fatalf("Expected valid decoding, got err: %v", err)
	}
	if dto.Name != "test_grant" || dto.Count != 5 {
		t.Fatalf("Unexpected DTO values: %+v", dto)
	}
}

func TestDecodeAndValidate_MalformedJSON(t *testing.T) {
	body := []byte(`{"name":`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))

	_, err := controller.DecodeAndValidate[SampleTestDTO](req)
	if err == nil {
		t.Fatal("Expected error for malformed JSON, got nil")
	}

	appErr, ok := err.(*controller.AppError)
	if !ok || appErr.Status != http.StatusBadRequest || appErr.Code != "INVALID_JSON" {
		t.Fatalf("Expected AppError with Status=400, Code=INVALID_JSON, got: %+v", err)
	}
}

func TestDecodeAndValidate_OversizedPayloadRejected(t *testing.T) {
	// Generate payload exceeding 1MB (1.5 MB)
	largeString := strings.Repeat("A", 1500000)
	body := []byte(`{"name":"` + largeString + `","count":1}`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))

	_, err := controller.DecodeAndValidate[SampleTestDTO](req)
	if err == nil {
		t.Fatal("Expected error for payload > 1MB, got nil")
	}

	appErr, ok := err.(*controller.AppError)
	if !ok || appErr.Status != http.StatusRequestEntityTooLarge || appErr.Code != "PAYLOAD_TOO_LARGE" {
		t.Fatalf("Expected AppError with Status=413 PAYLOAD_TOO_LARGE, got: %+v", err)
	}
}
