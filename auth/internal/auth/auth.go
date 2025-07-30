package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/bittensor-nexus/auth/internal/configuration"
)

// Auth represents the HTTP auth server
type Auth struct {
	config *configuration.Config
}

// NewAuth creates a new auth instance
func NewAuth(config *configuration.Config) *Auth {
	return &Auth{
		config: config,
	}
}

// Start starts the HTTP auth server
func (a *Auth) Start() error {
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

// authHandler validates mTLS client certificate from X-Client-Cert header
func (a *Auth) authHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request for debugging purposes
	log.Printf("Auth request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Get the client certificate from X-Client-Cert header
	clientCertHeader := r.Header.Get("X-Client-Cert")
	if clientCertHeader == "" {
		log.Printf("No X-Client-Cert header found")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: No client certificate"))
		return
	}

	// URL decode the certificate (nginx typically URL-encodes it)
	decodedCert, err := url.QueryUnescape(clientCertHeader)
	if err != nil {
		log.Printf("Failed to URL decode certificate: %v", err)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: Invalid certificate encoding"))
		return
	}

	// Parse the certificate
	cert, err := a.parseCertificate(decodedCert)
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: Invalid certificate"))
		return
	}

	// Extract Organization Name (O) from certificate
	orgName := a.extractOrganizationName(cert)
	if orgName == "" {
		log.Printf("No organization name found in certificate")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: No organization in certificate"))
		return
	}

	// Load the corresponding certificate
	expectedCert, err := a.loadCertificate(orgName)
	if err != nil {
		log.Printf("Failed to load certificate for organization '%s': %v", orgName, err)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: Organization not authorized"))
		return
	}

	// Validate the certificate against the expected certificate
	if err := a.validateCertificate(cert, expectedCert); err != nil {
		log.Printf("Certificate validation failed for organization '%s': %v", orgName, err)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: Certificate validation failed"))
		return
	}

	// Certificate is valid
	log.Printf("Certificate validation successful for organization '%s'", orgName)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access granted"))
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
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || char == ' ' || char == '-' || char == '_') {
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

// loadCertificate loads the certificate for the given organization from the certs directory
func (a *Auth) loadCertificate(orgName string) (*x509.Certificate, error) {
	// Sanitize the organization name to prevent path traversal attacks
	sanitizedOrgName, err := a.sanitizeOrgName(orgName)
	if err != nil {
		return nil, fmt.Errorf("invalid organization name: %v", err)
	}

	// Construct the path to the certificate file
	certPath := filepath.Join(a.config.GetCertsDirectory(), sanitizedOrgName+".crt")

	// Check if the file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}

	// Read the certificate file
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Parse the PEM-encoded certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// validateCertificate validates the certificate against the expected certificate
func (a *Auth) validateCertificate(cert *x509.Certificate, expectedCert *x509.Certificate) error {
	// Get the public key from both certificates
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an Ed25519 public key")
	}

	expectedPub, ok := expectedCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected certificate does not contain an Ed25519 public key")
	}

	// Compare the public keys (Ed25519 keys are byte slices)
	if len(certPub) != len(expectedPub) {
		return fmt.Errorf("certificate public key length does not match expected public key length")
	}

	for i := range certPub {
		if certPub[i] != expectedPub[i] {
			return fmt.Errorf("certificate public key does not match expected public key")
		}
	}

	// Additional validation: compare certificate subjects for extra security
	if cert.Subject.String() != expectedCert.Subject.String() {
		return fmt.Errorf("certificate subject does not match expected certificate subject")
	}

	// Note: We're not checking the certificate chain or CA validation here
	// as this is typically handled by the reverse proxy (nginx) before reaching this service

	return nil
}
