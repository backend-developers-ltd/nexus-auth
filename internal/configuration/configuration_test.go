package configuration

import (
	"flag"
	"os"
	"testing"
	"time"
)

// TestNewConfig tests the NewConfig function with defaults and env only (CLI flags ignored)
func TestNewConfig(t *testing.T) {
	// Save and restore original command line args; environment is managed per-subtest via t.Setenv
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
		// Reset flag package state
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	}()

	tests := []struct {
		name               string
		args               []string
		envListenAddr      string
		envPylonEndpoint   string
		expectedListenAddr string
		expectedPylon      string
	}{
		{
			name:               "default values",
			args:               []string{"program"},
			envListenAddr:      "",
			envPylonEndpoint:   "",
			expectedListenAddr: ":8080",
			expectedPylon:      "http://pylon:8000",
		},
		{
			name:               "environment variables only",
			args:               []string{"program"},
			envListenAddr:      ":9090",
			envPylonEndpoint:   "http://env-pylon:8080/",
			expectedListenAddr: ":9090",
			expectedPylon:      "http://env-pylon:8080/",
		},
		{
			name:               "CLI args are ignored in NewConfig",
			args:               []string{"program", "-listen-addr", ":7070", "-pylon-endpoint", "http://cli-pylon:8080/"},
			envListenAddr:      "",
			envPylonEndpoint:   "",
			expectedListenAddr: ":8080",
			expectedPylon:      "http://pylon:8000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag package state for each test
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			// Set up environment variables for this subtest
			if tt.envListenAddr != "" {
				t.Setenv("NEXUS_AUTH_LISTEN_ADDR", tt.envListenAddr)
			} else {
				t.Setenv("NEXUS_AUTH_LISTEN_ADDR", "")
			}

			if tt.envPylonEndpoint != "" {
				t.Setenv("NEXUS_PYLON_ENDPOINT", tt.envPylonEndpoint)
			} else {
				t.Setenv("NEXUS_PYLON_ENDPOINT", "")
			}

			// Set up command line arguments (should not affect NewConfig)
			os.Args = tt.args

			// Create config
			config := NewConfig()

			// Verify results
			if config.ListenAddr != tt.expectedListenAddr {
				t.Errorf("Expected ListenAddr %q, got %q", tt.expectedListenAddr, config.ListenAddr)
			}
			if config.PylonEndpoint != tt.expectedPylon {
				t.Errorf("Expected PylonEndpoint %q, got %q", tt.expectedPylon, config.PylonEndpoint)
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

// TestGetPylonEndpoint tests the GetPylonEndpoint method
func TestGetPylonEndpoint(t *testing.T) {
	tests := []struct {
		name          string
		pylonEndpoint string
		expected      string
	}{
		{
			name:          "default endpoint",
			pylonEndpoint: "http://pylon:8000",
			expected:      "http://pylon:8000",
		},
		{
			name:          "custom endpoint",
			pylonEndpoint: "http://custom-pylon:9000/",
			expected:      "http://custom-pylon:9000/",
		},
		{
			name:          "without trailing slash",
			pylonEndpoint: "http://pylon:8080",
			expected:      "http://pylon:8080",
		},
		{
			name:          "empty endpoint",
			pylonEndpoint: "",
			expected:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				PylonEndpoint: tt.pylonEndpoint,
			}

			result := config.GetPylonEndpoint()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestConfigStruct tests the Config struct initialization
func TestConfigStruct(t *testing.T) {
	config := &Config{
		ListenAddr:    ":8080",
		PylonEndpoint: "http://pylon:8000",
	}

	if config.ListenAddr != ":8080" {
		t.Errorf("Expected ListenAddr :8080, got %s", config.ListenAddr)
	}

	if config.PylonEndpoint != "http://pylon:8000" {
		t.Errorf("Expected PylonEndpoint http://pylon:8000, got %s", config.PylonEndpoint)
	}
}

// TestNewConfigDefaults tests that NewConfig sets proper defaults
func TestNewConfigDefaults(t *testing.T) {
	// Save original args and restore flags after test; environment managed via t.Setenv
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	}()

	// Clear environment and args
	os.Args = []string{"program"}
	t.Setenv("NEXUS_AUTH_LISTEN_ADDR", "")
	t.Setenv("NEXUS_PYLON_ENDPOINT", "")
	t.Setenv("NEXUS_PYLON_NETUID", "")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	config := NewConfig()

	expectedListenAddr := ":8080"
	expectedPylon := "http://pylon:8000"

	if config.ListenAddr != expectedListenAddr {
		t.Errorf("Expected default ListenAddr %q, got %q", expectedListenAddr, config.ListenAddr)
	}

	if config.PylonEndpoint != expectedPylon {
		t.Errorf("Expected default PylonEndpoint %q, got %q", expectedPylon, config.PylonEndpoint)
	}
}

// TestConfig_CacheDurationDefault tests default cache duration
func TestConfig_CacheDurationDefault(t *testing.T) {
	t.Setenv("NEXUS_AUTH_CACHE_DURATION_MINS", "")

	config := NewConfig()

	if config.CacheDurationMins != 15 {
		t.Errorf("Expected default cache duration 15 minutes, got %d", config.CacheDurationMins)
	}

	duration := config.GetCacheDuration()
	expected := 15 * time.Minute
	if duration != expected {
		t.Errorf("Expected cache duration %v, got %v", expected, duration)
	}
}

// TestConfig_CacheDurationFromEnv tests cache duration from environment
func TestConfig_CacheDurationFromEnv(t *testing.T) {
	t.Setenv("NEXUS_AUTH_CACHE_DURATION_MINS", "30")

	config := NewConfig()

	if config.CacheDurationMins != 30 {
		t.Errorf("Expected cache duration 30 minutes from env, got %d", config.CacheDurationMins)
	}

	duration := config.GetCacheDuration()
	expected := 30 * time.Minute
	if duration != expected {
		t.Errorf("Expected cache duration %v, got %v", expected, duration)
	}
}

// TestConfig_CacheDurationInvalidEnv tests invalid cache duration in environment
func TestConfig_CacheDurationInvalidEnv(t *testing.T) {
	t.Setenv("NEXUS_AUTH_CACHE_DURATION_MINS", "invalid")

	config := NewConfig()

	// Should fall back to default
	if config.CacheDurationMins != 15 {
		t.Errorf("Expected default cache duration 15 minutes for invalid env, got %d", config.CacheDurationMins)
	}
}

// TestConfig_NetUIDDefault tests that NetUID defaults to -1 when not set
func TestConfig_NetUIDDefault(t *testing.T) {
	t.Setenv("NEXUS_PYLON_NETUID", "")

	config := NewConfig()

	if config.NetUID != -1 {
		t.Errorf("Expected default NetUID -1, got %d", config.NetUID)
	}
}

// TestConfig_NetUIDFromEnv tests NetUID is read from NEXUS_PYLON_NETUID
func TestConfig_NetUIDFromEnv(t *testing.T) {
	t.Setenv("NEXUS_PYLON_NETUID", "42")

	config := NewConfig()

	if config.NetUID != 42 {
		t.Errorf("Expected NetUID 42 from env, got %d", config.NetUID)
	}
}

// TestConfig_NetUIDInvalidEnv tests invalid NEXUS_PYLON_NETUID falls back to -1
func TestConfig_NetUIDInvalidEnv(t *testing.T) {
	t.Setenv("NEXUS_PYLON_NETUID", "notanumber")

	config := NewConfig()

	if config.NetUID != -1 {
		t.Errorf("Expected default NetUID -1 for invalid env, got %d", config.NetUID)
	}
}

// TestConfig_CacheDurationNegativeEnv tests negative cache duration in environment
func TestConfig_CacheDurationNegativeEnv(t *testing.T) {
	t.Setenv("NEXUS_AUTH_CACHE_DURATION_MINS", "-10")

	config := NewConfig()

	// Should fall back to default for negative values
	if config.CacheDurationMins != 15 {
		t.Errorf("Expected default cache duration 15 minutes for negative env, got %d", config.CacheDurationMins)
	}
}

// TestConfig_CacheDurationZeroEnv tests zero cache duration in environment
func TestConfig_CacheDurationZeroEnv(t *testing.T) {
	t.Setenv("NEXUS_AUTH_CACHE_DURATION_MINS", "0")

	config := NewConfig()

	// Zero is valid (disables caching)
	if config.CacheDurationMins != 0 {
		t.Errorf("Expected cache duration 0 minutes from env, got %d", config.CacheDurationMins)
	}

	duration := config.GetCacheDuration()
	if duration != 0 {
		t.Errorf("Expected cache duration 0, got %v", duration)
	}
}
