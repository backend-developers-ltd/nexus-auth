package configuration

import (
	"flag"
	"os"
	"testing"
)

// TestNewConfig tests the NewConfig function with various scenarios
func TestNewConfig(t *testing.T) {
	// Save original command line args and environment
	originalArgs := os.Args
	originalEnvListenAddr := os.Getenv("NEXUS_LISTEN_ADDR")
	originalEnvCertsDir := os.Getenv("NEXUS_CERTS_DIR")

	// Clean up after test
	defer func() {
		os.Args = originalArgs
		if originalEnvListenAddr != "" {
			os.Setenv("NEXUS_LISTEN_ADDR", originalEnvListenAddr)
		} else {
			os.Unsetenv("NEXUS_LISTEN_ADDR")
		}
		if originalEnvCertsDir != "" {
			os.Setenv("NEXUS_CERTS_DIR", originalEnvCertsDir)
		} else {
			os.Unsetenv("NEXUS_CERTS_DIR")
		}
		// Reset flag package state
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	}()

	tests := []struct {
		name               string
		args               []string
		envListenAddr      string
		envCertsDir        string
		expectedListenAddr string
		expectedCerts      string
	}{
		{
			name:               "default values",
			args:               []string{"program"},
			envListenAddr:      "",
			envCertsDir:        "",
			expectedListenAddr: ":8080",
			expectedCerts:      "certs",
		},
		{
			name:               "environment variables only",
			args:               []string{"program"},
			envListenAddr:      ":9090",
			envCertsDir:        "/custom/certs",
			expectedListenAddr: ":9090",
			expectedCerts:      "/custom/certs",
		},
		{
			name:               "CLI args only",
			args:               []string{"program", "-listen-addr", ":7070", "-certs-dir", "/cli/certs"},
			envListenAddr:      "",
			envCertsDir:        "",
			expectedListenAddr: ":7070",
			expectedCerts:      "/cli/certs",
		},
		{
			name:               "CLI args override environment",
			args:               []string{"program", "-listen-addr", ":6060", "-certs-dir", "/override/certs"},
			envListenAddr:      ":9090",
			envCertsDir:        "/env/certs",
			expectedListenAddr: ":6060",
			expectedCerts:      "/override/certs",
		},
		{
			name:               "partial CLI override",
			args:               []string{"program", "-listen-addr", ":5050"},
			envListenAddr:      ":9090",
			envCertsDir:        "/env/certs",
			expectedListenAddr: ":5050",
			expectedCerts:      "/env/certs",
		},
		{
			name:               "partial environment override",
			args:               []string{"program"},
			envListenAddr:      ":4040",
			envCertsDir:        "",
			expectedListenAddr: ":4040",
			expectedCerts:      "certs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag package state for each test
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			// Set up environment variables
			if tt.envListenAddr != "" {
				os.Setenv("NEXUS_LISTEN_ADDR", tt.envListenAddr)
			} else {
				os.Unsetenv("NEXUS_LISTEN_ADDR")
			}

			if tt.envCertsDir != "" {
				os.Setenv("NEXUS_CERTS_DIR", tt.envCertsDir)
			} else {
				os.Unsetenv("NEXUS_CERTS_DIR")
			}

			// Set up command line arguments
			os.Args = tt.args

			// Create config
			config := NewConfig()

			// Verify results
			if config.ListenAddr != tt.expectedListenAddr {
				t.Errorf("Expected ListenAddr %q, got %q", tt.expectedListenAddr, config.ListenAddr)
			}

			if config.CertsDir != tt.expectedCerts {
				t.Errorf("Expected CertsDir %q, got %q", tt.expectedCerts, config.CertsDir)
			}
		})
	}
}

// TestGetListenAddress tests the GetListenAddress method
func TestGetListenAddress(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		expected   string
	}{
		{
			name:       "default port",
			listenAddr: ":8080",
			expected:   ":8080",
		},
		{
			name:       "custom port",
			listenAddr: ":9090",
			expected:   ":9090",
		},
		{
			name:       "full address",
			listenAddr: "localhost:8080",
			expected:   "localhost:8080",
		},
		{
			name:       "empty address",
			listenAddr: "",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ListenAddr: tt.listenAddr,
			}

			result := config.GetListenAddress()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestGetCertsDirectory tests the GetCertsDirectory method
func TestGetCertsDirectory(t *testing.T) {
	tests := []struct {
		name     string
		certsDir string
		expected string
	}{
		{
			name:     "default directory",
			certsDir: "certs",
			expected: "certs",
		},
		{
			name:     "custom directory",
			certsDir: "/custom/path/certs",
			expected: "/custom/path/certs",
		},
		{
			name:     "relative path",
			certsDir: "./certs",
			expected: "./certs",
		},
		{
			name:     "empty directory",
			certsDir: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				CertsDir: tt.certsDir,
			}

			result := config.GetCertsDirectory()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestConfigStruct tests the Config struct initialization
func TestConfigStruct(t *testing.T) {
	config := &Config{
		ListenAddr: ":8080",
		CertsDir:   "certs",
	}

	if config.ListenAddr != ":8080" {
		t.Errorf("Expected ListenAddr :8080, got %s", config.ListenAddr)
	}

	if config.CertsDir != "certs" {
		t.Errorf("Expected CertsDir certs, got %s", config.CertsDir)
	}
}

// TestNewConfigDefaults tests that NewConfig sets proper defaults
func TestNewConfigDefaults(t *testing.T) {
	// Save original state
	originalArgs := os.Args
	originalEnvListenAddr := os.Getenv("NEXUS_LISTEN_ADDR")
	originalEnvCertsDir := os.Getenv("NEXUS_CERTS_DIR")

	// Clean up after test
	defer func() {
		os.Args = originalArgs
		if originalEnvListenAddr != "" {
			os.Setenv("NEXUS_LISTEN_ADDR", originalEnvListenAddr)
		} else {
			os.Unsetenv("NEXUS_LISTEN_ADDR")
		}
		if originalEnvCertsDir != "" {
			os.Setenv("NEXUS_CERTS_DIR", originalEnvCertsDir)
		} else {
			os.Unsetenv("NEXUS_CERTS_DIR")
		}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	}()

	// Clear environment and args
	os.Args = []string{"program"}
	os.Unsetenv("NEXUS_LISTEN_ADDR")
	os.Unsetenv("NEXUS_CERTS_DIR")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	config := NewConfig()

	expectedListenAddr := ":8080"
	expectedCertsDir := "certs"

	if config.ListenAddr != expectedListenAddr {
		t.Errorf("Expected default ListenAddr %q, got %q", expectedListenAddr, config.ListenAddr)
	}

	if config.CertsDir != expectedCertsDir {
		t.Errorf("Expected default CertsDir %q, got %q", expectedCertsDir, config.CertsDir)
	}
}
