package configuration

import (
	"flag"
	"os"
)

// Config holds all configuration values for the auth service
type Config struct {
	ListenAddr string
	CertsDir   string
}

// NewConfig creates a new configuration instance with values from CLI args and environment variables
func NewConfig() *Config {
	config := &Config{
		ListenAddr: ":8080", // default HTTP port
		CertsDir:   "certs", // default certificates directory
	}

	// Parse CLI arguments
	listenAddrFlag := flag.String("listen-addr", config.ListenAddr, "Address to listen on")
	certsDirFlag := flag.String("certs-dir", config.CertsDir, "Directory containing certificate files")
	flag.Parse()

	// Check for environment variables
	if envListenAddr := os.Getenv("NEXUS_LISTEN_ADDR"); envListenAddr != "" {
		config.ListenAddr = envListenAddr
	}
	if envCertsDir := os.Getenv("NEXUS_CERTS_DIR"); envCertsDir != "" {
		config.CertsDir = envCertsDir
	}

	// CLI arguments take precedence over environment variables
	if flag.Lookup("listen-addr").Value.String() != flag.Lookup("listen-addr").DefValue {
		config.ListenAddr = *listenAddrFlag
	}
	if flag.Lookup("certs-dir").Value.String() != flag.Lookup("certs-dir").DefValue {
		config.CertsDir = *certsDirFlag
	}

	return config
}

// GetListenAddress returns the address string for ListenAndServe
func (c *Config) GetListenAddress() string {
	return c.ListenAddr
}

// GetCertsDirectory returns the directory path for certificate files
func (c *Config) GetCertsDirectory() string {
	return c.CertsDir
}
