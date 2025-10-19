package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/backend-developers-ltd/nexus-auth/internal/configuration"
	"github.com/backend-developers-ltd/nexus-auth/internal/pylon"
)

// Auth represents the HTTP auth server
type Auth struct {
	config      *configuration.Config
	pylonClient *pylon.Client
}

// NewAuth creates a new auth instance
func NewAuth(config *configuration.Config) *Auth {
	return &Auth{
		config:      config,
		pylonClient: pylon.New(config.GetPylonEndpoint()),
	}
}

// Run the HTTP auth server
func (a *Auth) Run() error {
	// Get configuration values
	httpAddr := a.config.GetListenAddress()

	log.Printf("Starting HTTP auth server on %s", httpAddr)

	// Create HTTP server with auth handler
	// TODO(maciek): add read/write timeouts
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: http.HandlerFunc(a.authHandler),
	}

	// Start the HTTP server (blocking)
	return httpServer.ListenAndServe()
}

// Generate requests Pylon to generate an Ed25519 keypair and writes client.key and client.crt into outputDir
// notAfterDays controls the validity period of the generated certificate (in days).
func (a *Auth) Generate(outputDir string, algorithm int, ss58Address string, notAfterDays int) error {
	resp, err := a.pylonClient.GenerateCertificateKeypair(pylon.GenerateCertificateKeypairRequest{Algorithm: algorithm})
	if err != nil {
		return fmt.Errorf("failed to generate certificate keypair: %w", err)
	}

	// Parse Ed25519 private key from hex (support 0x prefix, 32-byte seed or 64-byte private key)
	pkStr := strings.TrimSpace(resp.PrivateKey)
	pkStr = strings.TrimPrefix(pkStr, "0x")
	pkBytes, err := hex.DecodeString(pkStr)
	if err != nil {
		return fmt.Errorf("invalid private key hex from pylon: %w", err)
	}
	var priv ed25519.PrivateKey
	switch len(pkBytes) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(pkBytes)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(pkBytes)
	default:
		return fmt.Errorf("unexpected private key length %d", len(pkBytes))
	}

	// Build a self-signed X.509 certificate similar to scripts/certgen.py
	serialNumber := big.NewInt(1)
	now := time.Now()
	validDays := notAfterDays
	if validDays <= 0 {
		validDays = 365 * 10
	}
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{ss58Address}},
		NotBefore:    now,
		NotAfter:     now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	pub := priv.Public().(ed25519.PublicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode private key to PKCS#8 PEM
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	keyPath := filepath.Join(outputDir, "client.key")
	crtPath := filepath.Join(outputDir, "client.crt")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

// authHandler validates mTLS client certificate from X-Client-Cert header
func (a *Auth) authHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request for debugging purposes
	log.Printf("Auth request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Get the client certificate from X-Client-Cert header
	clientCertHeader := r.Header.Get("X-Client-Cert")
	if clientCertHeader == "" {
		log.Printf("No X-Client-Cert header found")
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Access denied: No client certificate")); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// URL decode the certificate (nginx typically URL-encodes it)
	decodedCert, err := url.QueryUnescape(clientCertHeader)
	if err != nil {
		log.Printf("Failed to URL decode certificate: %v", err)
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Access denied: Invalid certificate encoding")); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Parse the certificate
	cert, err := a.parseCertificate(decodedCert)
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Access denied: Invalid certificate")); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Extract Organization Name (O) from certificate
	orgName := a.extractOrganizationName(cert)
	if orgName == "" {
		log.Printf("No organization name found in certificate")
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Access denied: No organization in certificate")); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Load the expected public key from Pylon using the organization name as hotkey
	expectedPub, err := a.loadExpectedPublicKey(orgName)
	if err != nil {
		log.Printf("Failed to load expected public key for organization '%s': %v", orgName, err)
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Access denied: Organization not authorized")); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Validate the certificate against the expected public key
	if err := a.validatePublicKey(cert, expectedPub); err != nil {
		log.Printf("Certificate validation failed for organization '%s': %v", orgName, err)
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Access denied: Certificate validation failed")); err != nil {
			log.Printf("failed to write response body: %v", err)
		}
		return
	}

	// Certificate is valid
	log.Printf("Certificate validation successful for organization '%s'", orgName)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Access granted")); err != nil {
		log.Printf("failed to write response body: %v", err)
	}
}

// parseCertificate parses a PEM-encoded certificate
func (a *Auth) parseCertificate(certPEM string) (*x509.Certificate, error) {
	// Handle cases where the certificate might not have proper PEM headers
	if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") {
		certPEM = "-----BEGIN CERTIFICATE-----\n" + certPEM + "\n-----END CERTIFICATE-----"
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// extractOrganizationName extracts the Organization Name (O) from the certificate
func (a *Auth) extractOrganizationName(cert *x509.Certificate) string {
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return ""
}

// sanitizeOrgName sanitizes the organization name to prevent path traversal attacks
func (a *Auth) sanitizeOrgName(orgName string) (string, error) {
	// Check if orgName is empty
	if strings.TrimSpace(orgName) == "" {
		return "", fmt.Errorf("organization name cannot be empty")
	}

	// Remove any path separators and traversal sequences
	sanitized := strings.ReplaceAll(orgName, "/", "")
	sanitized = strings.ReplaceAll(sanitized, "\\", "")
	sanitized = strings.ReplaceAll(sanitized, "..", "")

	// Check for invalid characters - only allow alphanumeric, spaces, hyphens, and underscores
	for _, char := range sanitized {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != ' ' && char != '-' && char != '_' {
			return "", fmt.Errorf("organization name contains invalid characters")
		}
	}

	// Trim whitespace and check if anything is left
	sanitized = strings.TrimSpace(sanitized)
	if sanitized == "" {
		return "", fmt.Errorf("organization name is empty after sanitization")
	}

	return sanitized, nil
}

// loadExpectedPublicKey fetches expected ed25519 public key for given organization (hotkey) from Pylon
func (a *Auth) loadExpectedPublicKey(orgName string) (ed25519.PublicKey, error) {
	// Sanitize the organization name to prevent path traversal attacks
	sanitizedOrgName, err := a.sanitizeOrgName(orgName)
	if err != nil {
		return nil, fmt.Errorf("invalid organization name: %v", err)
	}

	resp, err := a.pylonClient.GetCertificate(sanitizedOrgName)
	if err != nil {
		return nil, err
	}
	if resp.Algorithm != 1 {
		return nil, fmt.Errorf("unsupported algorithm: %d", resp.Algorithm)
	}
	if strings.TrimSpace(resp.PublicKey) == "" {
		return nil, fmt.Errorf("pylon response missing public_key")
	}

	decoded, err := hex.DecodeString(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public_key as hex: %v", err)
	}
	return ed25519.PublicKey(decoded), nil
}

// validatePublicKey validates the certificate's public key against the expected public key
func (a *Auth) validatePublicKey(cert *x509.Certificate, expectedPub ed25519.PublicKey) error {
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an Ed25519 public key")
	}

	if len(certPub) != len(expectedPub) {
		return fmt.Errorf("certificate public key length does not match expected public key length")
	}
	for i := range certPub {
		if certPub[i] != expectedPub[i] {
			return fmt.Errorf("certificate public key does not match expected public key")
		}
	}
	return nil
}
