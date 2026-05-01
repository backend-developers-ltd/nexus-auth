package pylon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNew verifies default HTTP client and base URL propagation
func TestNew(t *testing.T) {
	c := New("http://example/", 1, "test-identity", "test-token")
	if c == nil {
		t.Fatalf("New returned nil")
	}
	if c.BaseURL != "http://example/" {
		t.Errorf("BaseURL not set, got %q", c.BaseURL)
	}
	if c.NetUID != 1 {
		t.Errorf("NetUID not set, got %d", c.NetUID)
	}
	if c.IdentityName != "test-identity" {
		t.Errorf("IdentityName not set, got %q", c.IdentityName)
	}
	if c.IdentityToken != "test-token" {
		t.Errorf("IdentityToken not set, got %q", c.IdentityToken)
	}
	if c.HTTPClient == nil {
		t.Fatalf("HTTPClient should be initialized")
	}
	if c.HTTPClient.Timeout == 0 {
		t.Errorf("expected non-zero timeout on HTTP client")
	}
}

// TestGetCertificate covers success and various error paths
func TestGetCertificate(t *testing.T) {
	handler := func(code int, payload any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			if payload != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(payload)
			}
		}
	}

	// Success server (algorithm 1)
	success := httptest.NewServer(handler(http.StatusOK, map[string]any{"public_key": "abc", "algorithm": 1}))
	defer success.Close()

	// Non-200 server
	non200 := httptest.NewServer(handler(http.StatusTeapot, nil))
	defer non200.Close()

	// Invalid JSON server
	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "not-json")
	}))
	defer invalidJSON.Close()

	// Timeout server using a custom client with tiny timeout
	timeoutSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer timeoutSrv.Close()

	tests := []struct {
		name      string
		baseURL   string
		hotkey    string
		clientTwe func(*Client)
		wantKey   string
		wantErr   bool
	}{
		{
			name:    "success with trailing slash",
			baseURL: success.URL + "/",
			hotkey:  "hk",
			wantKey: "abc",
		},
		{
			name:    "success without trailing slash",
			baseURL: success.URL,
			hotkey:  "hk",
			wantKey: "abc",
		},
		{
			name:    "non-200 status",
			baseURL: non200.URL,
			hotkey:  "hk",
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			baseURL: invalidJSON.URL,
			hotkey:  "hk",
			wantErr: true,
		},
		{
			name:    "empty hotkey",
			baseURL: success.URL,
			hotkey:  "",
			wantErr: true,
		},
		{
			name:    "empty base URL",
			baseURL: "",
			hotkey:  "hk",
			wantErr: true,
		},
		{
			name:    "request timeout",
			baseURL: timeoutSrv.URL,
			hotkey:  "hk",
			clientTwe: func(c *Client) {
				c.HTTPClient.Timeout = 50 * time.Millisecond
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.baseURL, 1, "test-identity", "test-token")
			if tt.clientTwe != nil {
				tt.clientTwe(c)
			}
			resp, err := c.GetCertificate(tt.hotkey)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none; resp=%+v", resp)
				}
				if resp != nil {
					t.Fatalf("expected nil resp on error, got: %+v", resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil {
				t.Fatalf("expected non-nil resp on success")
			}
			if resp.PublicKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, resp.PublicKey)
			}
			if resp.Algorithm != 1 {
				t.Fatalf("expected alghoritm 1, got %d", resp.Algorithm)
			}
		})
	}
}

// TestGenerateCertificateKeypair validates POSTing to self endpoint with algorithm-only body
func TestGenerateCertificateKeypair(t *testing.T) {
	var gotPath, gotMethod string
	var gotReq GenerateCertificateKeypairRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"public_key":  "pk",
			"private_key": "sk",
			"algorithm":   gotReq.Algorithm,
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 1, "test-identity", "test-token")
	resp, err := c.GenerateCertificateKeypair(GenerateCertificateKeypairRequest{Algorithm: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/v1/identity/test-identity/subnet/1/certificates/self" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("unexpected method: %s", gotMethod)
	}
	if gotReq.Algorithm != 2 {
		t.Fatalf("expected algorithm 2 in request, got %d", gotReq.Algorithm)
	}
	if resp == nil || resp.PublicKey != "pk" || resp.PrivateKey != "sk" || resp.Algorithm != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGenerateCertificateKeypair_Errors(t *testing.T) {
	// empty identity name
	c := New("http://example.com", 1, "", "test-token")
	resp, err := c.GenerateCertificateKeypair(GenerateCertificateKeypairRequest{Algorithm: 1})
	if err == nil || resp != nil {
		t.Fatalf("expected error on empty identity name, got resp=%+v err=%v", resp, err)
	}

	// non-200
	non200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer non200.Close()

	c = New(non200.URL, 1, "test-identity", "test-token")
	resp, err = c.GenerateCertificateKeypair(GenerateCertificateKeypairRequest{Algorithm: 1})
	if err == nil || resp != nil {
		t.Fatalf("expected error on non-200, got resp=%+v err=%v", resp, err)
	}

	// invalid JSON response
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "not-json")
	}))
	defer badJSON.Close()

	c = New(badJSON.URL, 1, "test-identity", "test-token")
	resp, err = c.GenerateCertificateKeypair(GenerateCertificateKeypairRequest{Algorithm: 3})
	if err == nil || resp != nil {
		t.Fatalf("expected error on bad json, got resp=%+v err=%v", resp, err)
	}

	// empty base URL
	c = New("", 1, "test-identity", "test-token")
	resp, err = c.GenerateCertificateKeypair(GenerateCertificateKeypairRequest{Algorithm: 1})
	if err == nil || resp != nil {
		t.Fatalf("expected error on empty base url, got resp=%+v err=%v", resp, err)
	}

	// timeout
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer slow.Close()

	c = New(slow.URL, 1, "test-identity", "test-token")
	c.HTTPClient.Timeout = 50 * time.Millisecond
	resp, err = c.GenerateCertificateKeypair(GenerateCertificateKeypairRequest{Algorithm: 1})
	if err == nil || resp != nil {
		t.Fatalf("expected timeout error, got resp=%+v err=%v", resp, err)
	}
}

// New tests for GetOwnCertificate
func TestGetOwnCertificate(t *testing.T) {
	var gotPath, gotMethod string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"public_key": "selfpk",
			"algorithm":  7,
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 1, "test-identity", "test-token")
	resp, err := c.GetOwnCertificate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/v1/identity/test-identity/subnet/1/block/latest/certificates/self" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("unexpected method: %s", gotMethod)
	}
	if resp == nil || resp.PublicKey != "selfpk" || resp.Algorithm != 7 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGetOwnCertificate_Errors(t *testing.T) {
	// non-200
	non200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer non200.Close()

	c := New(non200.URL, 1, "test-identity", "test-token")
	resp, err := c.GetOwnCertificate()
	if err == nil || resp != nil {
		t.Fatalf("expected error on non-200, got resp=%+v err=%v", resp, err)
	}

	// invalid JSON response
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "not-json")
	}))
	defer badJSON.Close()

	c = New(badJSON.URL, 1, "test-identity", "test-token")
	resp, err = c.GetOwnCertificate()
	if err == nil || resp != nil {
		t.Fatalf("expected error on bad json, got resp=%+v err=%v", resp, err)
	}

	// empty base URL
	c = New("", 1, "test-identity", "test-token")
	resp, err = c.GetOwnCertificate()
	if err == nil || resp != nil {
		t.Fatalf("expected error on empty base url, got resp=%+v err=%v", resp, err)
	}

	// timeout
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer slow.Close()

	c = New(slow.URL, 1, "test-identity", "test-token")
	c.HTTPClient.Timeout = 50 * time.Millisecond
	resp, err = c.GetOwnCertificate()
	if err == nil || resp != nil {
		t.Fatalf("expected timeout error, got resp=%+v err=%v", resp, err)
	}
}
