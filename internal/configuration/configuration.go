package configuration

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration values for the auth service
type Config struct {
	ListenAddr        string
	PylonEndpoint     string
	CacheDurationMins int
}

// NewConfig creates a new configuration instance with defaults and environment variables only
// Command-line flags must NOT be handled here.
func NewConfig() *Config {
	config := &Config{
		ListenAddr:        ":8080",             // default HTTP port
		PylonEndpoint:     "http://pylon:8000", // default Pylon endpoint
		CacheDurationMins: 15,                  // default cache duration in minutes
	}

	// Environment variables override defaults
	if envListenAddr := os.Getenv("NEXUS_AUTH_LISTEN_ADDR"); envListenAddr != "" {
		config.ListenAddr = envListenAddr
	}
	if envPylonEndpoint := os.Getenv("NEXUS_PYLON_ENDPOINT"); envPylonEndpoint != "" {
		config.PylonEndpoint = envPylonEndpoint
	}
	if envCacheDuration := os.Getenv("NEXUS_AUTH_CACHE_DURATION_MINS"); envCacheDuration != "" {
		if val, err := strconv.Atoi(envCacheDuration); err == nil && val >= 0 {
			config.CacheDurationMins = val
		}
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

// GetCacheDuration returns the cache duration as a time.Duration
func (c *Config) GetCacheDuration() time.Duration {
	return time.Duration(c.CacheDurationMins) * time.Minute
}
