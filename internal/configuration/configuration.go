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
	NetUID            int
	IdentityName      string
	IdentityToken     string
}

// NewConfig creates a new configuration instance with defaults and environment variables only
// Command-line flags must NOT be handled here.
func NewConfig() *Config {
	config := &Config{
		ListenAddr:        ":8080",             // default HTTP port
		PylonEndpoint:     "http://pylon:8000", // default Pylon endpoint
		CacheDurationMins: 15,                  // default cache duration in minutes
		NetUID:            -1,                  // -1 means not set
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
	if envNetUID := os.Getenv("NEXUS_PYLON_NETUID"); envNetUID != "" {
		if val, err := strconv.Atoi(envNetUID); err == nil {
			config.NetUID = val
		}
	}
	if envIdentityName := os.Getenv("NEXUS_PYLON_IDENTITY_NAME"); envIdentityName != "" {
		config.IdentityName = envIdentityName
	}
	if envIdentityToken := os.Getenv("NEXUS_PYLON_IDENTITY_TOKEN"); envIdentityToken != "" {
		config.IdentityToken = envIdentityToken
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

// GetNetUID returns the subnet UID used for certificate lookup
func (c *Config) GetNetUID() int {
	return c.NetUID
}

// SetListenAddress mutates the listen address; used by CLI layer to override env/defaults.
func (c *Config) SetListenAddress(addr string) {
	c.ListenAddr = addr
}

// SetPylonEndpoint mutates the pylon endpoint; used by CLI layer to override env/defaults.
func (c *Config) SetPylonEndpoint(endpoint string) {
	c.PylonEndpoint = endpoint
}

// SetNetUID mutates the subnet UID; used by CLI layer to override env/defaults.
func (c *Config) SetNetUID(netUID int) {
	c.NetUID = netUID
}

// SetIdentityName sets the identity name; only needed for the generate subcommand.
func (c *Config) SetIdentityName(name string) {
	c.IdentityName = name
}

// GetIdentityToken returns the Bearer token for authenticating with pylon identity endpoints.
func (c *Config) GetIdentityToken() string {
	return c.IdentityToken
}

// SetIdentityToken sets the identity token; used by CLI layer to override env/defaults.
func (c *Config) SetIdentityToken(t string) {
	c.IdentityToken = t
}

// GetCacheDuration returns the cache duration as a time.Duration
func (c *Config) GetCacheDuration() time.Duration {
	return time.Duration(c.CacheDurationMins) * time.Minute
}
