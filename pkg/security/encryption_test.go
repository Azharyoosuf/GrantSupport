package security_test

import (
	"context"
	"testing"

	"grantsupport/pkg/security"
)

func TestLocalEncryptionDecryption(t *testing.T) {
	ctx := context.Background()
	plaintext := "sensitive_support_agent_token_12345"
	institutionID := "11111111-1111-1111-1111-111111111111"

	encrypted, err := security.Encrypt(ctx, plaintext, institutionID)
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("Encrypted output should not match raw plaintext")
	}

	decrypted, err := security.Decrypt(ctx, encrypted, institutionID)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted text '%s', got '%s'", plaintext, decrypted)
	}
}
