package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
	"github.com/backend-developers-ltd/nexus-auth/internal/pylon"
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

// TestLoadExpectedPublicKey tests fetching and decoding public key from Pylon
func TestLoadExpectedPublicKey(t *testing.T) {
	// Generate a test ed25519 key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	validKeyHex := hex.EncodeToString(pub)

	// Mock Pylon server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "/valid"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"public_key":"%s","algorithm":1}`, validKeyHex)
		case strings.Contains(p, "/invalid"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"public_key":"nothex","algorithm":1}`))
		case strings.Contains(p, "/missing"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"foo":"bar"}`))
		case strings.Contains(p, "/wrongalgo"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"public_key":"abcd","algorithm":2}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1}
	a := &Auth{
		config:      config,
		pylonClient: pylon.New(config.PylonEndpoint, config.NetUID, config.IdentityName, config.IdentityToken),
		cache:       NewPublicKeyCache(config.GetCacheDuration()),
	}

	tests := []struct {
		name        string
		orgName     string
		expectError bool
	}{
		{name: "success", orgName: "valid", expectError: false},
		{name: "invalid encoding", orgName: "invalid", expectError: true},
		{name: "missing key", orgName: "missing", expectError: true},
		{name: "wrong algorithm", orgName: "wrongalgo", expectError: true},
		{name: "not found", orgName: "unknown", expectError: true},
		{name: "empty", orgName: "", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := a.loadExpectedPublicKey(tt.orgName)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				if pubKey != nil {
					t.Fatalf("expected nil pubKey on error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(pubKey) == 0 {
					t.Fatalf("expected non-empty pubKey")
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
func TestValidatePublicKey(t *testing.T) {
	auth := &Auth{}

	// Generate test key pairs
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Create certificates with different keys
	cert1 := createTestCertificateWithKey(t, "Test Org", priv1)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		expectedPub ed25519.PublicKey
		expectError bool
	}{
		{
			name:        "matching public key",
			cert:        cert1,
			expectedPub: pub1,
			expectError: false,
		},
		{
			name:        "non-matching public key",
			cert:        cert1,
			expectedPub: pub2,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validatePublicKey(tt.cert, tt.expectedPub)
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
	// Create test key pair and certificate
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	testCert := createTestCertificateWithKey(t, "Test Organization", privateKey)

	// Prepare Pylon mock server that returns the public key for Test Organization
	testPub := testCert.PublicKey.(ed25519.PublicKey)
	testPubHex := hex.EncodeToString(testPub)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/Test Organization") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"public_key":"%s","algorithm":1}`, testPubHex)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Create auth instance configured to use mocked Pylon
	config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1}
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

// New tests for Auth.Generate
func TestGenerate_Success(t *testing.T) {
	// Prepare a deterministic 32-byte seed for ed25519
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	seedHex := hex.EncodeToString(seed)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/identity/test-identity/subnet/1/certificates/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"algorithm":1,"public_key":"IGNORED","private_key":"%s"}`, seedHex)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1, IdentityName: "test-identity"}
	a := NewAuth(config)

	outDir := t.TempDir()
	ss58 := "TEST_SS58_ADDRESS"

	if err := a.Generate(ss58, outDir, 1, 3650, false); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	// Check files exist
	keyPath := filepath.Join(outDir, "client.key")
	crtPath := filepath.Join(outDir, "client.crt")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file, got error: %v", err)
	}
	if _, err := os.Stat(crtPath); err != nil {
		t.Fatalf("expected cert file, got error: %v", err)
	}

	// Parse certificate and verify subject Organization
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		t.Fatalf("read crt failed: %v", err)
	}
	block, _ := pem.Decode(crtPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("invalid cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert failed: %v", err)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != ss58 {
		t.Fatalf("unexpected subject organization: %+v", cert.Subject)
	}
}

func TestGenerate_PropagatesErrors(t *testing.T) {
	t.Run("pylon error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/identity/test-identity/subnet/1/certificates/self", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1, IdentityName: "test-identity"}
		a := NewAuth(config)

		outDir := t.TempDir()
		if err := a.Generate("ADDR", outDir, 1, 3650, false); err == nil {
			t.Fatalf("expected error but got nil")
		}
	})

	t.Run("file creation error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/identity/test-identity/subnet/1/certificates/self", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Return a minimal valid 32-byte seed as hex
			seed := make([]byte, ed25519.SeedSize)
			for i := range seed {
				seed[i] = byte(i)
			}
			_, _ = fmt.Fprintf(w, `{"algorithm":1,"public_key":"IGNORED","private_key":"%s"}`, hex.EncodeToString(seed))
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1, IdentityName: "test-identity"}
		a := NewAuth(config)

		// Create an output path that is a file (so MkdirAll will fail)
		f, err := os.CreateTemp(t.TempDir(), "outfile")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		_ = f.Close()
		outDir := f.Name()
		if err := a.Generate("ADDR", outDir, 1, 3650, false); err == nil {
			t.Fatalf("expected error due to invalid output dir but got nil")
		}
	})
}

func TestGenerate_SkipWhenFilesExist_NoForce(t *testing.T) {
	// Pylon server that fails if called; we expect no call when skipping
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/identity/test-identity/subnet/1/certificates/self", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1, IdentityName: "test-identity"}
	a := NewAuth(config)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	crtPath := filepath.Join(dir, "client.crt")

	origKey := []byte("ORIGINAL-KEY")
	origCrt := []byte("ORIGINAL-CRT")
	if err := os.WriteFile(keyPath, origKey, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(crtPath, origCrt, 0o644); err != nil {
		t.Fatalf("write crt: %v", err)
	}

	// Should skip and not call Pylon
	if err := a.Generate("ADDR", dir, 1, 3650, false); err != nil {
		t.Fatalf("Generate returned error on skip: %v", err)
	}
	if called {
		t.Fatalf("expected no call to pylon when files exist and force=false")
	}

	// Ensure files unchanged
	k2, _ := os.ReadFile(keyPath)
	c2, _ := os.ReadFile(crtPath)
	if string(k2) != string(origKey) || string(c2) != string(origCrt) {
		t.Fatalf("files were modified despite skip")
	}
}

func TestGenerate_ForceRecreate_WhenFilesExist(t *testing.T) {
	// Deterministic seed
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	seedHex := hex.EncodeToString(seed)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/identity/test-identity/subnet/1/certificates/self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"algorithm":1,"public_key":"IGN","private_key":"%s"}`, seedHex)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	config := &configuration.Config{PylonEndpoint: ts.URL + "/", NetUID: 1, IdentityName: "test-identity"}
	a := NewAuth(config)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	crtPath := filepath.Join(dir, "client.crt")

	_ = os.WriteFile(keyPath, []byte("OLDKEY"), 0o600)
	_ = os.WriteFile(crtPath, []byte("OLDCRT"), 0o644)

	if err := a.Generate("ADDR", dir, 1, 3650, true); err != nil {
		t.Fatalf("Generate with force failed: %v", err)
	}

	k2, _ := os.ReadFile(keyPath)
	c2, _ := os.ReadFile(crtPath)
	if string(k2) == "OLDKEY" || string(c2) == "OLDCRT" {
		t.Fatalf("expected files to be overwritten with force=true")
	}
}
