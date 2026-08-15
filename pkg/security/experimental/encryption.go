// Package experimental provides envelope and AEAD field encryption utilities.
package experimental

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/hkdf"
)

// LocalEncryptionService provides tenant-isolated AES-256-GCM authenticated encryption using HKDF derived keys.
type LocalEncryptionService struct {
	masterKey string
}

// NewLocalEncryptionService constructs a LocalEncryptionService with a given master key.
func NewLocalEncryptionService(masterKey string) *LocalEncryptionService {
	if masterKey == "" {
		masterKey = "0123456789abcdef0123456789abcdef"
	}
	return &LocalEncryptionService{masterKey: masterKey}
}

// Encrypt encrypts plaintext scoped to institutionID.
func (s *LocalEncryptionService) Encrypt(plaintext, institutionID string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	derivedKey, err := deriveTenantKey(s.masterKey, institutionID)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(institutionID))
	return "local:" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext scoped to institutionID.
func (s *LocalEncryptionService) Decrypt(ciphertext, institutionID string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if !strings.HasPrefix(ciphertext, "local:") {
		return "", errors.New("INVALID_CIPHERTEXT: Unknown encryption prefix")
	}

	rawCiphertext := strings.TrimPrefix(ciphertext, "local:")
	data, err := base64.StdEncoding.DecodeString(rawCiphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	derivedKey, err := deriveTenantKey(s.masterKey, institutionID)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("INVALID_CIPHERTEXT: Ciphertext too short")
	}

	nonce, actualCiphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, []byte(institutionID))
	if err != nil {
		return "", fmt.Errorf("decryption failed (possible key mismatch or data tampering): %w", err)
	}

	return string(plaintext), nil
}

// KMSEnryptionService provides AWS KMS envelope encryption.
type KMSEncryptionService struct {
	kmsKeyID string
	client   *kms.Client
}

// NewKMSEncryptionService constructs a KMSEncryptionService instance.
func NewKMSEncryptionService(ctx context.Context, region, kmsKeyID string) (*KMSEncryptionService, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}
	return &KMSEncryptionService{
		kmsKeyID: kmsKeyID,
		client:   kms.NewFromConfig(cfg),
	}, nil
}

// EncryptWithKMS encrypts plaintext using AWS KMS GenerateDataKey envelope encryption.
func (s *KMSEncryptionService) EncryptWithKMS(ctx context.Context, plaintext, institutionID string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	out, err := s.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &s.kmsKeyID,
		KeySpec: types.DataKeySpecAes256,
		EncryptionContext: map[string]string{
			"institutionId": institutionID,
		},
	})
	if err != nil {
		return "", fmt.Errorf("KMS GenerateDataKey failed: %w", err)
	}

	block, err := aes.NewCipher(out.Plaintext)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(institutionID))
	encryptedKeyB64 := base64.StdEncoding.EncodeToString(out.CiphertextBlob)
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	return fmt.Sprintf("kms:%s:%s", encryptedKeyB64, ciphertextB64), nil
}

func deriveTenantKey(masterKey, institutionID string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, []byte(masterKey), []byte(institutionID), []byte("grantsupport-tenant-key"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, err
	}
	return derivedKey, nil
}
