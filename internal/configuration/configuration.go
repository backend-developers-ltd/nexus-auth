package configuration

import (
	"os"
)

// Config holds all configuration values for the auth service
type Config struct {
	ListenAddr    string
	PylonEndpoint string
}

// NewConfig creates a new configuration instance with defaults and environment variables only
// Command-line flags must NOT be handled here.
func NewConfig() *Config {
	config := &Config{
		ListenAddr:    ":8080",             // default HTTP port
		PylonEndpoint: "http://pylon:8000", // default Pylon endpoint
	}

	// Environment variables override defaults
	if envListenAddr := os.Getenv("NEXUS_AUTH_LISTEN_ADDR"); envListenAddr != "" {
		config.ListenAddr = envListenAddr
	}
	if envPylonEndpoint := os.Getenv("NEXUS_PYLON_ENDPOINT"); envPylonEndpoint != "" {
		config.PylonEndpoint = envPylonEndpoint
	}

	return config
}

// GetListenAddress returns the address string for ListenAndServe
func (c *Config) GetListenAddress() string {
	return c.ListenAddr
}

// GetPylonEndpoint returns the base URL for the Pylon service
func (c *Config) GetPylonEndpoint() string {
	return c.PylonEndpoint
}

// SetListenAddress mutates the listen address; used by CLI layer to override env/defaults.
func (c *Config) SetListenAddress(addr string) {
	c.ListenAddr = addr
}

// SetPylonEndpoint mutates the pylon endpoint; used by CLI layer to override env/defaults.
func (c *Config) SetPylonEndpoint(endpoint string) {
	c.PylonEndpoint = endpoint
}
