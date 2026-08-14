// Package security provides cryptographic and transport security configurations for GrantSupport.
package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	ErrTLSCertificateNotFound = errors.New("TLS_CERT_NOT_FOUND: Certificate file not found or unreadable")
	ErrTLSKeyNotFound         = errors.New("TLS_KEY_NOT_FOUND: Private key file not found or unreadable")
	ErrTLSCertificateExpired  = errors.New("TLS_CERT_EXPIRED: Certificate is expired or not yet valid")
	ErrTLSCertificateInvalid  = errors.New("TLS_CERT_INVALID: Certificate failed validation for server authentication")
)

// NewServerTLSConfig constructs a hardened 2026-compliant *tls.Config from certificate and private key files.
func NewServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" {
		return nil, ErrTLSCertificateNotFound
	}
	if keyFile == "" {
		return nil, ErrTLSKeyNotFound
	}

	if _, err := os.Stat(certFile); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLSCertificateNotFound, err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLSKeyNotFound, err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS keypair: %w", err)
	}

	if len(cert.Certificate) == 0 {
		return nil, ErrTLSCertificateInvalid
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	now := time.Now()
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("%w: valid from %s to %s (current: %s)", ErrTLSCertificateExpired, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	cert.Leaf = leaf

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"}, // Enable HTTP/2 ALPN negotiation
	}

	return tlsConfig, nil
}

// GenerateTestTLSCertificate generates an ephemeral self-signed ECDSA certificate for isolated tests.
func GenerateTestTLSCertificate(hosts ...string) (tls.Certificate, []byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GrantSupport Test Suite"},
			CommonName:   "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to construct tls.Certificate: %w", err)
	}

	return tlsCert, certPEM, keyPEM, nil
}
