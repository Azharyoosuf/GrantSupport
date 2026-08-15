package experimental_test

import (
	"strings"
	"testing"

	"grantsupport/pkg/security/experimental"
)

func TestLocalEncryptionDecryption(t *testing.T) {
	svc := experimental.NewLocalEncryptionService("master-test-key-32bytes-secret!!")
	plaintext := "sensitive_support_agent_token_12345"
	institutionID := "11111111-1111-1111-1111-111111111111"

	encrypted, err := svc.Encrypt(plaintext, institutionID)
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("Encrypted output should not match raw plaintext")
	}

	decrypted, err := svc.Decrypt(encrypted, institutionID)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted text '%s', got '%s'", plaintext, decrypted)
	}
}

func TestEncryptionPersistenceAcrossRestart(t *testing.T) {
	plaintext := "persistent_pii_payload_data_999"
	institutionID := "22222222-2222-2222-2222-222222222222"

	svc1 := experimental.NewLocalEncryptionService("persistent-secret-key-32bytes!!")
	ciphertext, err := svc1.Encrypt(plaintext, institutionID)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Simulate restart with identical persistent key
	svc2 := experimental.NewLocalEncryptionService("persistent-secret-key-32bytes!!")
	decrypted, err := svc2.Decrypt(ciphertext, institutionID)
	if err != nil {
		t.Fatalf("Decryption after simulated restart failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("Decrypted payload %q did not match original %q", decrypted, plaintext)
	}

	// Cross-Tenant Decryption Isolation (Tenant B cannot decrypt Tenant A's ciphertext)
	otherTenantID := "33333333-3333-3333-3333-333333333333"
	_, err = svc2.Decrypt(ciphertext, otherTenantID)
	if err == nil {
		t.Fatal("Expected decryption to fail for different tenant ID due to HKDF key isolation")
	}

	// Corrupted Ciphertext Fails Closed
	tampered := strings.Replace(ciphertext, "local:", "local:corrupted", 1)
	_, err = svc2.Decrypt(tampered, institutionID)
	if err == nil {
		t.Fatal("Expected decryption of tampered ciphertext to fail closed")
	}
}
