package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-developers-ltd/nexus-auth/internal/configuration"
)

// TestNewAuth tests the NewAuth constructor
func TestNewAuth(t *testing.T) {
	config := &configuration.Config{}
	auth := NewAuth(config)

	if auth == nil {
		t.Fatal("NewAuth returned nil")
	}

	if auth.config != config {
		t.Error("NewAuth did not set config correctly")
	}
}

// TestParseCertificate tests certificate parsing functionality
func TestParseCertificate(t *testing.T) {
	auth := &Auth{}

	// Create a test certificate
	testCert := createTestCertificate(t, "Test Organization")
	certPEM := encodeCertificateToPEM(testCert)

	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "valid certificate with headers",
			input:       certPEM,
			expectError: false,
		},
		{
			name:        "valid certificate without headers",
			input:       strings.Replace(strings.Replace(certPEM, "-----BEGIN CERTIFICATE-----\n", "", 1), "\n-----END CERTIFICATE-----", "", 1),
			expectError: false,
		},
		{
			name:        "invalid certificate data",
			input:       "invalid-certificate-data",
			expectError: true,
		},
		{
			name:        "empty certificate",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := auth.parseCertificate(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if cert != nil {
					t.Error("Expected nil certificate on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if cert == nil {
					t.Error("Expected certificate but got nil")
				}
			}
		})
	}
}

// TestExtractOrganizationName tests organization name extraction
func TestExtractOrganizationName(t *testing.T) {
	auth := &Auth{}

	tests := []struct {
		name     string
		orgNames []string
		expected string
	}{
		{
			name:     "single organization",
			orgNames: []string{"Test Organization"},
			expected: "Test Organization",
		},
		{
			name:     "multiple organizations",
			orgNames: []string{"First Org", "Second Org"},
			expected: "First Org",
		},
		{
			name:     "no organizations",
			orgNames: []string{},
			expected: "",
		},
		{
			name:     "nil organizations",
			orgNames: nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				Subject: pkix.Name{
					Organization: tt.orgNames,
				},
			}

			result := auth.extractOrganizationName(cert)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestLoadCertificate tests certificate loading functionality
func TestLoadCertificate(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := ioutil.TempDir("", "auth_test_certs")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test certificate
	cert := createTestCertificate(t, "Test Organization")

	// Save certificate to file
	certPEM := encodeCertificateToPEM(cert)
	certPath := filepath.Join(tempDir, "Test Organization.crt")
	err = ioutil.WriteFile(certPath, []byte(certPEM), 0644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	// Create config with temp directory
	config := &configuration.Config{}
	config.CertsDir = tempDir
	auth := &Auth{config: config}

	tests := []struct {
		name        string
		orgName     string
		expectError bool
		errorType   string // for more specific error checking
	}{
		{
			name:        "existing organization",
			orgName:     "Test Organization",
			expectError: false,
			errorType:   "",
		},
		{
			name:        "non-existing organization",
			orgName:     "Non Existing Org",
			expectError: true,
			errorType:   "not found",
		},
		{
			name:        "empty organization name",
			orgName:     "",
			expectError: true,
			errorType:   "invalid organization name",
		},
		{
			name:        "path traversal with forward slashes",
			orgName:     "../../etc/passwd",
			expectError: true,
			errorType:   "not found", // sanitized to "etcpasswd" but file doesn't exist
		},
		{
			name:        "path traversal with backslashes",
			orgName:     "..\\..\\windows\\system32",
			expectError: true,
			errorType:   "not found", // sanitized to "windowssystem32" but file doesn't exist
		},
		{
			name:        "path traversal with mixed separators",
			orgName:     "../..\\etc/shadow",
			expectError: true,
			errorType:   "not found", // sanitized to "etcshadow" but file doesn't exist
		},
		{
			name:        "organization with special characters",
			orgName:     "org@#$%^&*()",
			expectError: true,
			errorType:   "invalid organization name",
		},
		{
			name:        "organization with only dots",
			orgName:     "...",
			expectError: true,
			errorType:   "invalid organization name",
		},
		{
			name:        "whitespace only organization",
			orgName:     "   ",
			expectError: true,
			errorType:   "invalid organization name",
		},
		{
			name:        "organization with slashes gets sanitized but file not found",
			orgName:     "org/with/slashes",
			expectError: true,
			errorType:   "not found", // sanitized to "orgwithslashes" but file doesn't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadedCert, err := auth.loadCertificate(tt.orgName)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if loadedCert != nil {
					t.Error("Expected nil certificate on error")
				}
				// Check for specific error types
				if tt.errorType != "" {
					if !strings.Contains(err.Error(), tt.errorType) {
						t.Errorf("Expected error containing %q, got %q", tt.errorType, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if loadedCert == nil {
					t.Error("Expected certificate but got nil")
				}
			}
		})
	}
}

// TestSanitizeOrgName tests organization name sanitization for security
func TestSanitizeOrgName(t *testing.T) {
	auth := &Auth{}

	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "valid organization name",
			input:       "Test Organization",
			expected:    "Test Organization",
			expectError: false,
		},
		{
			name:        "organization with hyphens and underscores",
			input:       "Test-Org_123",
			expected:    "Test-Org_123",
			expectError: false,
		},
		{
			name:        "path traversal with forward slashes",
			input:       "../../etc/passwd",
			expected:    "etcpasswd",
			expectError: false,
		},
		{
			name:        "path traversal with backslashes",
			input:       "..\\..\\windows\\system32",
			expected:    "windowssystem32",
			expectError: false,
		},
		{
			name:        "path traversal with mixed separators",
			input:       "../..\\etc/shadow",
			expected:    "etcshadow",
			expectError: false,
		},
		{
			name:        "organization with dots",
			input:       "org..with..dots",
			expected:    "orgwithdots",
			expectError: false,
		},
		{
			name:        "organization with slashes",
			input:       "org/with/slashes",
			expected:    "orgwithslashes",
			expectError: false,
		},
		{
			name:        "organization with backslashes",
			input:       "org\\with\\backslashes",
			expected:    "orgwithbackslashes",
			expectError: false,
		},
		{
			name:        "empty string",
			input:       "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "whitespace only",
			input:       "   ",
			expected:    "",
			expectError: true,
		},
		{
			name:        "organization with special characters",
			input:       "org@#$%^&*()",
			expected:    "",
			expectError: true,
		},
		{
			name:        "organization with leading/trailing spaces",
			input:       "  Test Organization  ",
			expected:    "Test Organization",
			expectError: false,
		},
		{
			name:        "organization becomes empty after sanitization",
			input:       "../..",
			expected:    "",
			expectError: true,
		},
		{
			name:        "organization with only invalid characters",
			input:       "@#$%^&*()",
			expected:    "",
			expectError: true,
		},
		{
			name:        "long valid organization name",
			input:       "Very Long Organization Name With Spaces And Numbers 123",
			expected:    "Very Long Organization Name With Spaces And Numbers 123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auth.sanitizeOrgName(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if result != "" {
					t.Errorf("Expected empty result on error, got %q", result)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected %q, got %q", tt.expected, result)
				}
			}
		})
	}
}

// TestValidateCertificate tests certificate validation
func TestValidateCertificate(t *testing.T) {
	auth := &Auth{}

	// Generate test key pairs
	_, privateKey1, _ := ed25519.GenerateKey(rand.Reader)
	_, privateKey2, _ := ed25519.GenerateKey(rand.Reader)

	// Create certificates with different keys
	cert1 := createTestCertificateWithKey(t, "Test Org", privateKey1)
	cert2 := createTestCertificateWithKey(t, "Test Org", privateKey2)
	cert3 := createTestCertificateWithKey(t, "Different Org", privateKey1)

	tests := []struct {
		name         string
		cert         *x509.Certificate
		expectedCert *x509.Certificate
		expectError  bool
	}{
		{
			name:         "matching certificates",
			cert:         cert1,
			expectedCert: cert1,
			expectError:  false,
		},
		{
			name:         "non-matching certificates",
			cert:         cert1,
			expectedCert: cert2,
			expectError:  true,
		},
		{
			name:         "same key different subject",
			cert:         cert1,
			expectedCert: cert3,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateCertificate(tt.cert, tt.expectedCert)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestAuthHandler tests the HTTP auth handler
func TestAuthHandler(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := ioutil.TempDir("", "auth_test_certs")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test key pair and certificate
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	testCert := createTestCertificateWithKey(t, "Test Organization", privateKey)

	// Save certificate to file
	certPEM := encodeCertificateToPEM(testCert)
	certPath := filepath.Join(tempDir, "Test Organization.crt")
	err = ioutil.WriteFile(certPath, []byte(certPEM), 0644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	// Create auth instance
	config := &configuration.Config{}
	config.CertsDir = tempDir
	auth := NewAuth(config)

	// Create certificates with malicious organization names for security testing
	maliciousCert1 := createTestCertificateWithKey(t, "../../etc/passwd", privateKey)
	maliciousCert2 := createTestCertificateWithKey(t, "..\\..\\windows\\system32", privateKey)
	maliciousCert3 := createTestCertificateWithKey(t, "org@#$%^&*()", privateKey)

	// Test cases
	tests := []struct {
		name           string
		clientCert     string
		expectedStatus int
		description    string
	}{
		{
			name:           "valid certificate",
			clientCert:     url.QueryEscape(encodeCertificateToPEM(testCert)),
			expectedStatus: http.StatusOK,
			description:    "legitimate certificate should be accepted",
		},
		{
			name:           "no certificate header",
			clientCert:     "",
			expectedStatus: http.StatusForbidden,
			description:    "missing certificate should be rejected",
		},
		{
			name:           "invalid certificate",
			clientCert:     url.QueryEscape("invalid-cert-data"),
			expectedStatus: http.StatusForbidden,
			description:    "malformed certificate should be rejected",
		},
		{
			name:           "certificate with path traversal organization name",
			clientCert:     url.QueryEscape(encodeCertificateToPEM(maliciousCert1)),
			expectedStatus: http.StatusForbidden,
			description:    "certificate with path traversal org name should be rejected",
		},
		{
			name:           "certificate with backslash path traversal",
			clientCert:     url.QueryEscape(encodeCertificateToPEM(maliciousCert2)),
			expectedStatus: http.StatusForbidden,
			description:    "certificate with backslash traversal should be rejected",
		},
		{
			name:           "certificate with special characters in org name",
			clientCert:     url.QueryEscape(encodeCertificateToPEM(maliciousCert3)),
			expectedStatus: http.StatusForbidden,
			description:    "certificate with special characters should be rejected",
		},
		{
			name:           "certificate without organization",
			clientCert:     url.QueryEscape(encodeCertificateToPEM(createTestCertificateWithKey(t, "", privateKey))),
			expectedStatus: http.StatusForbidden,
			description:    "certificate without organization should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.clientCert != "" {
				req.Header.Set("X-Client-Cert", tt.clientCert)
			}

			rr := httptest.NewRecorder()
			auth.authHandler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// Helper functions for testing

func createTestCertificate(t *testing.T, orgName string) *x509.Certificate {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	return createTestCertificateWithKey(t, orgName, privateKey)
}

func createTestCertificateWithKey(t *testing.T, orgName string, privateKey ed25519.PrivateKey) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
	}

	// For Ed25519, the public key is derived from the private key
	publicKey := privateKey.Public().(ed25519.PublicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func encodeCertificateToPEM(cert *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(certPEM)
}

func encodePublicKeyToPEM(publicKey ed25519.PublicKey) string {
	publicKeyDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})
	return string(publicKeyPEM)
}
