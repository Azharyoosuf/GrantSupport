package security_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"grantsupport/pkg/security"
)

// TestTLS_ValidCertificateAndKey verifies successful TLS configuration creation with valid cert and key files.
func TestTLS_ValidCertificateAndKey(t *testing.T) {
	_, certPEM, keyPEM, err := security.GenerateTestTLSCertificate("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	tlsConfig, err := security.NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("Expected successful TLS config creation, got: %v", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("Expected MinVersion tls.VersionTLS12, got %x", tlsConfig.MinVersion)
	}

	// Verify HTTP/2 ALPN is configured
	hasH2 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h2" {
			hasH2 = true
			break
		}
	}
	if !hasH2 {
		t.Fatal("Expected 'h2' in NextProtos for HTTP/2 support")
	}
}

// TestTLS_MissingOrUnreadableFiles verifies fail-startup behavior when certificate or key files do not exist.
func TestTLS_MissingOrUnreadableFiles(t *testing.T) {
	tempDir := t.TempDir()
	existingCert := filepath.Join(tempDir, "existing.crt")
	_ = os.WriteFile(existingCert, []byte("dummy"), 0600)

	t.Run("Missing Certificate File", func(t *testing.T) {
		_, err := security.NewServerTLSConfig("/nonexistent/path/server.crt", existingCert)
		if err == nil || !errors.Is(err, security.ErrTLSCertificateNotFound) {
			t.Fatalf("Expected ErrTLSCertificateNotFound, got: %v", err)
		}
	})

	t.Run("Missing Private Key File", func(t *testing.T) {
		_, err := security.NewServerTLSConfig(existingCert, "/nonexistent/path/server.key")
		if err == nil || !errors.Is(err, security.ErrTLSKeyNotFound) {
			t.Fatalf("Expected ErrTLSKeyNotFound, got: %v", err)
		}
	})
}

// TestTLS_MismatchedKeypair verifies that a mismatched cert and key fails startup.
func TestTLS_MismatchedKeypair(t *testing.T) {
	_, certPEM1, _, _ := security.GenerateTestTLSCertificate("127.0.0.1")
	_, _, keyPEM2, _ := security.GenerateTestTLSCertificate("127.0.0.1")

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert1.crt")
	keyFile := filepath.Join(tempDir, "key2.key")

	_ = os.WriteFile(certFile, certPEM1, 0600)
	_ = os.WriteFile(keyFile, keyPEM2, 0600)

	_, err := security.NewServerTLSConfig(certFile, keyFile)
	if err == nil {
		t.Fatal("Expected error when loading mismatched certificate and private key, got nil")
	}
}

// TestTLS_ExpiredCertificate verifies that expired certificates are detected and rejected on startup.
func TestTLS_ExpiredCertificate(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Expired yesterday
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "expired.crt")
	keyFile := filepath.Join(tempDir, "expired.key")

	_ = os.WriteFile(certFile, certPEM, 0600)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	_, err := security.NewServerTLSConfig(certFile, keyFile)
	if err == nil || !errors.Is(err, security.ErrTLSCertificateExpired) {
		t.Fatalf("Expected ErrTLSCertificateExpired, got: %v", err)
	}
}

// TestTLS_VersionNegotiationAndRejection verifies TLS 1.2 and TLS 1.3 connections succeed while legacy TLS versions are rejected.
func TestTLS_VersionNegotiationAndRejection(t *testing.T) {
	tlsCert, certPEM, keyPEM, err := security.GenerateTestTLSCertificate("127.0.0.1")
	if err != nil {
		t.Fatalf("GenerateTestTLSCertificate failed: %v", err)
	}

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	_ = os.WriteFile(certFile, certPEM, 0600)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	tlsConfig, err := security.NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TLS_OK"))
	}))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	// Parse server cert for client trust pool
	certPool := x509.NewCertPool()
	leafCert, _ := x509.ParseCertificate(tlsCert.Certificate[0])
	certPool.AddCert(leafCert)

	t.Run("TLS 1.3 Connection -> Success", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					MinVersion: tls.VersionTLS13,
					MaxVersion: tls.VersionTLS13,
				},
			},
		}

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("TLS 1.3 request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK over TLS 1.3, got %d", resp.StatusCode)
		}
		if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("Expected negotiated TLS 1.3 (0x%x), got 0x%x", tls.VersionTLS13, resp.TLS.Version)
		}
	})

	t.Run("TLS 1.2 Connection -> Success", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS12,
				},
			},
		}

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("TLS 1.2 request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK over TLS 1.2, got %d", resp.StatusCode)
		}
		if resp.TLS.Version != tls.VersionTLS12 {
			t.Fatalf("Expected negotiated TLS 1.2 (0x%x), got 0x%x", tls.VersionTLS12, resp.TLS.Version)
		}
	})

	t.Run("TLS 1.0 / 1.1 Connection -> Rejected by Server", func(t *testing.T) {
		// Attempting handshake with MaxVersion = TLS 1.1 must fail because server MinVersion is TLS 1.2
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					MaxVersion: tls.VersionTLS11,
				},
			},
		}

		_, err := client.Get(server.URL)
		if err == nil {
			t.Fatal("Security Violation: Server accepted legacy TLS 1.1 connection; expected handshake failure")
		}
	})
}
