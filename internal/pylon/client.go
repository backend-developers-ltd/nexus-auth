package pylon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const httpTimeout = 300 * time.Second

// Client is a minimal HTTP client for interacting with the Pylon service
// BaseURL should be something like "http://pylon:8000" (with or without trailing slash)
type Client struct {
	BaseURL       string
	NetUID        int
	IdentityName  string
	IdentityToken string
	HTTPClient    *http.Client
}

// GenerateCertificateKeypairRequest is the request body for generating a new keypair
// It contains only the desired algorithm.
type GenerateCertificateKeypairRequest struct {
	Algorithm int `json:"algorithm"`
}

// CertificateResponse represents the response from Pylon for a certificate lookup
// (public information only)
type CertificateResponse struct {
	Algorithm int    `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// CertificateKeypairResponse represents the response from Pylon for keypair generation
// It includes the public and private key material.
type CertificateKeypairResponse struct {
	Algorithm  int    `json:"algorithm"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// New creates a new Pylon client with sane defaults
func New(baseURL string, netUID int, identityName string, identityToken string) *Client {
	return &Client{
		BaseURL:       baseURL,
		NetUID:        netUID,
		IdentityName:  identityName,
		IdentityToken: identityToken,
		HTTPClient:    &http.Client{Timeout: httpTimeout},
	}
}

// GetCertificate fetches public certificate data for provided hotkey
// It performs a GET {BaseURL}/api/v1/identity/{identity_name}/subnet/{netuid}/block/latest/certificates/{hotkey}
// Returns the whole CertificateResponse struct
func (c *Client) GetCertificate(hotkey string) (*CertificateResponse, error) {
	if strings.TrimSpace(hotkey) == "" {
		return nil, fmt.Errorf("hotkey cannot be empty")
	}

	base, err := c.baseURLNormalized()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/identity/%s/subnet/%d/block/latest/certificates/%s", base, c.IdentityName, c.NetUID, hotkey)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.IdentityToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pylon returned status %d", resp.StatusCode)
	}

	var body CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding response failed: %w", err)
	}

	return &body, nil
}

// GetOwnCertificate fetches public certificate data for the identity's wallet (self)
// It performs a GET {BaseURL}/api/v1/identity/{identity_name}/subnet/{netuid}/block/latest/certificates/self
// Returns the whole CertificateResponse struct
func (c *Client) GetOwnCertificate() (*CertificateResponse, error) {
	base, err := c.baseURLNormalized()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/identity/%s/subnet/%d/block/latest/certificates/self", base, c.IdentityName, c.NetUID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.IdentityToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pylon returned status %d", resp.StatusCode)
	}

	var body CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding response failed: %w", err)
	}

	return &body, nil
}

// GenerateCertificateKeypair generates a new certificate keypair using Pylon
// It performs a POST {BaseURL}/api/v1/identity/{identity_name}/subnet/{netuid}/certificates/self
// Returns the CertificateKeypairResponse from Pylon
func (c *Client) GenerateCertificateKeypair(reqBody GenerateCertificateKeypairRequest) (*CertificateKeypairResponse, error) {
	if strings.TrimSpace(c.IdentityName) == "" {
		return nil, fmt.Errorf("identity name is required for certificate generation")
	}

	base, err := c.baseURLNormalized()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/identity/%s/subnet/%d/certificates/self", base, c.IdentityName, c.NetUID)

	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(reqBody); err != nil {
		return nil, fmt.Errorf("encoding request failed: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		return nil, fmt.Errorf("creating request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.IdentityToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("pylon returned status %d", resp.StatusCode)
	}

	var body CertificateKeypairResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding response failed: %w", err)
	}
	return &body, nil
}

// baseURLNormalized returns the base URL trimmed and WITHOUT a trailing slash
func (c *Client) baseURLNormalized() (string, error) {
	base := strings.TrimSpace(c.BaseURL)
	// Remove any trailing slash to keep a canonical form
	base = strings.TrimRight(base, "/")
	if base == "" {
		return "", fmt.Errorf("pylon base URL is empty")
	}
	return base, nil
}
