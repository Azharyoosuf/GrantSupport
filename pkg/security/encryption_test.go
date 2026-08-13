package security_test

import (
	"context"
	"strings"
	"testing"

	pkgconfig "grantsupport/pkg/config"
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

func TestEncryptionPersistenceAcrossRestart(t *testing.T) {
	ctx := context.Background()
	plaintext := "persistent_pii_payload_data_999"
	institutionID := "22222222-2222-2222-2222-222222222222"

	// 1. Initial configuration
	pkgconfig.AppConfig.MasterEncryptionKey = "persistent-secret-key-32bytes!!"
	pkgconfig.AppConfig.EncryptionProvider = "LOCAL"

	ciphertext, err := security.Encrypt(ctx, plaintext, institutionID)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 2. Simulate Application Restart with identical persistent key
	pkgconfig.AppConfig.MasterEncryptionKey = "persistent-secret-key-32bytes!!"
	decrypted, err := security.Decrypt(ctx, ciphertext, institutionID)
	if err != nil {
		t.Fatalf("Decryption after simulated restart failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("Decrypted payload %q did not match original %q", decrypted, plaintext)
	}

	// 3. Cross-Tenant Decryption Isolation (Tenant B cannot decrypt Tenant A's ciphertext)
	otherTenantID := "33333333-3333-3333-3333-333333333333"
	_, err = security.Decrypt(ctx, ciphertext, otherTenantID)
	if err == nil {
		t.Fatal("Expected decryption to fail for different tenant ID due to HKDF key isolation")
	}

	// 4. Corrupted Ciphertext Fails Closed
	tampered := strings.Replace(ciphertext, "local:", "local:corrupted", 1)
	_, err = security.Decrypt(ctx, tampered, institutionID)
	if err == nil {
		t.Fatal("Expected decryption of tampered ciphertext to fail closed")
	}
}
