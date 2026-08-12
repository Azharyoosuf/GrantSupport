package security

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

	pkgconfig "grantsupport/pkg/config"
)

var kmsClient *kms.Client

// getKmsClient initializes the AWS KMS client pool.
func getKmsClient(ctx context.Context) (*kms.Client, error) {
	if kmsClient != nil {
		return kmsClient, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(pkgconfig.AppConfig.AWSRegion))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}
	kmsClient = kms.NewFromConfig(cfg)
	return kmsClient, nil
}

// Encrypt encrypts a plaintext string using either AWS KMS or Local HKDF GCM fallback.
func Encrypt(ctx context.Context, plaintext string, institutionID string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	provider := pkgconfig.AppConfig.EncryptionProvider

	if provider == "AWS_KMS" {
		kmsKeyID := pkgconfig.AppConfig.KmsKeyID
		if kmsKeyID == "" {
			return "", errors.New("KMS_KEY_ID is missing in configuration")
		}

		client, err := getKmsClient(ctx)
		if err != nil {
			return "", err
		}

		res, err := client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:   &kmsKeyID,
			KeySpec: types.DataKeySpecAes256,
			EncryptionContext: map[string]string{
				"institutionId": institutionID,
			},
		})
		if err != nil {
			return "", fmt.Errorf("KMS GenerateDataKey failed: %w", err)
		}

		plaintextKey := res.Plaintext
		encryptedDekBase64 := base64.StdEncoding.EncodeToString(res.CiphertextBlob)

		iv := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}

		block, err := aes.NewCipher(plaintextKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
		ciphertext := sealed[:len(sealed)-16]
		tag := sealed[len(sealed)-16:]

		// Wipe plaintext key from memory
		for i := range plaintextKey {
			plaintextKey[i] = 0
		}

		ivBase64 := base64.StdEncoding.EncodeToString(iv)
		ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
		tagBase64 := base64.StdEncoding.EncodeToString(tag)

		return fmt.Sprintf("kms:%s:%s:%s:%s", encryptedDekBase64, ivBase64, ciphertextBase64, tagBase64), nil

	} else {
		// Fallback LOCAL mode (HKDF + AES-256-GCM)
		masterKey := pkgconfig.AppConfig.MasterEncryptionKey
		masterKeyHash := sha256.Sum256([]byte(masterKey))

		kdf := hkdf.New(sha256.New, masterKeyHash[:], []byte(institutionID), []byte("SUPPORT_GRANT_ENCRYPTION"))
		derivedKey := make([]byte, 32)
		if _, err := io.ReadFull(kdf, derivedKey); err != nil {
			return "", fmt.Errorf("HKDF key derivation failed: %w", err)
		}

		iv := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}

		block, err := aes.NewCipher(derivedKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
		ciphertext := sealed[:len(sealed)-16]
		tag := sealed[len(sealed)-16:]

		ivBase64 := base64.StdEncoding.EncodeToString(iv)
		ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
		tagBase64 := base64.StdEncoding.EncodeToString(tag)

		return fmt.Sprintf("local:%s:%s:%s", ivBase64, ciphertextBase64, tagBase64), nil
	}
}

// Decrypt decrypts a formatted ciphertext string.
func Decrypt(ctx context.Context, ciphertext string, institutionID string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	parts := strings.Split(ciphertext, ":")
	if len(parts) == 0 {
		return "", errors.New("malformed encrypted payload")
	}

	provider := parts[0]

	if provider == "kms" {
		if len(parts) != 5 {
			return "", errors.New("malformed KMS encrypted payload")
		}

		encryptedDekBase64 := parts[1]
		ivBase64 := parts[2]
		cipherTextBase64 := parts[3]
		tagBase64 := parts[4]

		encryptedDek, err := base64.StdEncoding.DecodeString(encryptedDekBase64)
		if err != nil {
			return "", fmt.Errorf("invalid KMS DEK encoding: %w", err)
		}

		client, err := getKmsClient(ctx)
		if err != nil {
			return "", err
		}

		res, err := client.Decrypt(ctx, &kms.DecryptInput{
			CiphertextBlob: encryptedDek,
			EncryptionContext: map[string]string{
				"institutionId": institutionID,
			},
		})
		if err != nil {
			return "", fmt.Errorf("KMS Decrypt failed: %w", err)
		}

		plaintextKey := res.Plaintext

		iv, err := base64.StdEncoding.DecodeString(ivBase64)
		if err != nil {
			return "", fmt.Errorf("invalid IV encoding: %w", err)
		}

		ciphertextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
		if err != nil {
			return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
		}

		tagBytes, err := base64.StdEncoding.DecodeString(tagBase64)
		if err != nil {
			return "", fmt.Errorf("invalid tag encoding: %w", err)
		}

		block, err := aes.NewCipher(plaintextKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := append(ciphertextBytes, tagBytes...)
		plaintext, err := gcm.Open(nil, iv, sealed, nil)

		// Wipe plaintext key from memory
		for i := range plaintextKey {
			plaintextKey[i] = 0
		}

		if err != nil {
			return "", fmt.Errorf("GCM decryption failed: %w", err)
		}

		return string(plaintext), nil

	} else if provider == "local" {
		if len(parts) != 4 {
			return "", errors.New("malformed Local encrypted payload")
		}

		ivBase64 := parts[1]
		cipherTextBase64 := parts[2]
		tagBase64 := parts[3]

		masterKey := pkgconfig.AppConfig.MasterEncryptionKey
		masterKeyHash := sha256.Sum256([]byte(masterKey))

		kdf := hkdf.New(sha256.New, masterKeyHash[:], []byte(institutionID), []byte("SUPPORT_GRANT_ENCRYPTION"))
		derivedKey := make([]byte, 32)
		if _, err := io.ReadFull(kdf, derivedKey); err != nil {
			return "", fmt.Errorf("HKDF key derivation failed: %w", err)
		}

		iv, err := base64.StdEncoding.DecodeString(ivBase64)
		if err != nil {
			return "", fmt.Errorf("invalid IV encoding: %w", err)
		}

		ciphertextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
		if err != nil {
			return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
		}

		tagBytes, err := base64.StdEncoding.DecodeString(tagBase64)
		if err != nil {
			return "", fmt.Errorf("invalid tag encoding: %w", err)
		}

		block, err := aes.NewCipher(derivedKey)
		if err != nil {
			return "", err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		sealed := append(ciphertextBytes, tagBytes...)
		plaintext, err := gcm.Open(nil, iv, sealed, nil)
		if err != nil {
			return "", fmt.Errorf("GCM decryption failed: %w", err)
		}

		return string(plaintext), nil
	}

	return ciphertext, nil
}
