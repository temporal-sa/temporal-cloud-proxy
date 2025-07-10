package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewConfigManager(t *testing.T) {
	tests := []struct {
		name        string
		configData  string
		wantErr     bool
		expectNil   bool
		description string
	}{
		{
			name: "valid config file",
			configData: `
server:
  port: 7233
  host: "0.0.0.0"
workloads:
  - workload_id: "test.internal"
    temporal_cloud:
      namespace: "test-namespace"
      host_port: "test.external:7233"
      authentication:
        tls:
          cert_file: "/path/to/cert.crt"
          key_file: "/path/to/key.key"
    encryption_key: "test-key"
`,
			wantErr:     false,
			expectNil:   false,
			description: "should successfully create config manager with valid config",
		},
		{
			name: "minimal valid config",
			configData: `
server:
  port: 8080
  host: "localhost"
workloads: []
`,
			wantErr:     false,
			expectNil:   false,
			description: "should handle minimal config with empty workloads",
		},
		{
			name: "invalid yaml",
			configData: `
server:
  port: 7233
  host: "0.0.0.0"
targets:
  - proxy_id: "test.internal"
    target: "test.external:7233"
    invalid: yaml: [
`,
			wantErr:     true,
			expectNil:   true,
			description: "should fail with invalid YAML",
		},
		{
			name:        "empty config file",
			configData:  "",
			wantErr:     false,
			expectNil:   false,
			description: "should handle empty config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configPath, []byte(tt.configData), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			cm, err := NewConfigManager(configPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfigManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (cm == nil) != tt.expectNil {
				t.Errorf("NewConfigManager() returned nil = %v, expectNil %v", cm == nil, tt.expectNil)
				return
			}

			if !tt.wantErr && cm != nil {
				// Verify the config manager was properly initialized
				if cm.configPath != configPath {
					t.Errorf("Expected configPath to be %s, got %s", configPath, cm.configPath)
				}

				config := cm.GetConfig()
				if config == nil {
					t.Error("Expected GetConfig() to return non-nil config")
				}

				// Verify lastLoadTime was set
				if cm.lastLoadTime.IsZero() {
					t.Error("Expected lastLoadTime to be set")
				}
			}
		})
	}
}

func TestNewConfigManager_FileNotFound(t *testing.T) {
	nonExistentPath := "/path/that/does/not/exist/config.yaml"

	cm, err := NewConfigManager(nonExistentPath)

	if err == nil {
		t.Error("Expected error when config file does not exist")
	}

	if cm != nil {
		t.Error("Expected ConfigManager to be nil when file does not exist")
	}
}

func TestConfigManager_GetConfig(t *testing.T) {
	configData := `
server:
  port: 9090
  host: "127.0.0.1"
workloads:
  - workload_id: "test1.internal"
    temporal_cloud:
      namespace: "namespace1"
      host_port: "test1.external:9090"
      authentication:
        tls:
          cert_file: "/test1.crt"
          key_file: "/test1.key"
    encryption_key: "key1"
  - workload_id: "test2.internal"
    temporal_cloud:
      namespace: "namespace2"
      host_port: "test2.external:9091"
      authentication:
        tls:
          cert_file: "/test2.crt"
          key_file: "/test2.key"
    encryption_key: "key2"
    authentication:
      type: "spiffe"
      config:
        trust_domain: "spiffe://example.org/"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to create ConfigManager: %v", err)
	}

	config := cm.GetConfig()

	if config == nil {
		t.Fatal("GetConfig() returned nil")
	}

	// Verify server config
	if config.Server.Port != 9090 {
		t.Errorf("Expected server port to be 9090, got %d", config.Server.Port)
	}
	if config.Server.Host != "127.0.0.1" {
		t.Errorf("Expected server host to be '127.0.0.1', got %s", config.Server.Host)
	}

	// Verify workloads
	if len(config.Workloads) != 2 {
		t.Errorf("Expected 2 workloads, got %d", len(config.Workloads))
	}

	if len(config.Workloads) >= 1 {
		workload1 := config.Workloads[0]
		if workload1.WorkloadId != "test1.internal" {
			t.Errorf("Expected first workload workload_id to be 'test1.internal', got %s", workload1.WorkloadId)
		}
		if workload1.Authentication != nil {
			t.Error("Expected first workload to have no authentication")
		}
	}

	if len(config.Workloads) >= 2 {
		workload2 := config.Workloads[1]
		if workload2.WorkloadId != "test2.internal" {
			t.Errorf("Expected second workload workload_id to be 'test2.internal', got %s", workload2.WorkloadId)
		}
		if workload2.Authentication == nil {
			t.Error("Expected second workload to have authentication")
		} else if workload2.Authentication.Type != "spiffe" {
			t.Errorf("Expected second workload auth type to be 'spiffe', got %s", workload2.Authentication.Type)
		}
	}
}

func TestConfigManager_GetConfig_ThreadSafety(t *testing.T) {
	configData := `
server:
  port: 8080
  host: "localhost"
workloads:
  - workload_id: "concurrent.internal"
    temporal_cloud:
      namespace: "concurrent-namespace"
      host_port: "concurrent.external:8080"
      authentication:
        tls:
          cert_file: "/concurrent.crt"
          key_file: "/concurrent.key"
    encryption_key: "concurrent-key"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to create ConfigManager: %v", err)
	}

	// Test concurrent access to GetConfig
	const numGoroutines = 100
	const numIterations = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				config := cm.GetConfig()
				if config == nil {
					errors <- err
					return
				}
				if config.Server.Port != 8080 {
					errors <- err
					return
				}
				if len(config.Workloads) != 1 {
					errors <- err
					return
				}
				if config.Workloads[0].WorkloadId != "concurrent.internal" {
					errors <- err
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent access error: %v", err)
		}
	}
}

func TestConfigManager_Close(t *testing.T) {
	configData := `
server:
  port: 7233
  host: "0.0.0.0"
targets: []
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to create ConfigManager: %v", err)
	}

	// Test that Close() doesn't return an error
	err = cm.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Test that we can still get config after Close() (since Close() is currently a no-op)
	config := cm.GetConfig()
	if config == nil {
		t.Error("GetConfig() returned nil after Close()")
	}
}

func TestConfigManager_loadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configData  string
		wantErr     bool
		description string
	}{
		{
			name: "valid config",
			configData: `
server:
  port: 7233
  host: "0.0.0.0"
targets:
  - proxy_id: "test.internal"
    target: "test.external:7233"
    tls:
      cert_file: "/path/to/cert.crt"
      key_file: "/path/to/key.key"
    encryption_key: "test-key"
    namespace: "test-namespace"
`,
			wantErr:     false,
			description: "should load valid config successfully",
		},
		{
			name: "invalid yaml structure",
			configData: `
server:
  port: "invalid_port"  # port should be int, not string
  host: "0.0.0.0"
targets: []
`,
			wantErr:     true,
			description: "should fail with invalid YAML structure",
		},
		{
			name: "malformed yaml",
			configData: `
server:
  port: 7233
  host: "0.0.0.0"
targets:
  - proxy_id: "test.internal"
    target: "test.external:7233"
    invalid: [unclosed
`,
			wantErr:     true,
			description: "should fail with malformed YAML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configPath, []byte(tt.configData), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			cm := &ConfigManager{
				configPath: configPath,
			}

			beforeLoad := time.Now()
			err = cm.loadConfig()
			afterLoad := time.Now()

			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify config was loaded
				if cm.config == nil {
					t.Error("Expected config to be loaded")
				}

				// Verify lastLoadTime was updated
				if cm.lastLoadTime.Before(beforeLoad) || cm.lastLoadTime.After(afterLoad) {
					t.Error("Expected lastLoadTime to be updated during load")
				}
			}
		})
	}
}

func TestConfigManager_loadConfig_FilePermissions(t *testing.T) {
	configData := `
server:
  port: 7233
  host: "0.0.0.0"
targets: []
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Remove read permissions
	err = os.Chmod(configPath, 0000)
	if err != nil {
		t.Fatalf("Failed to change file permissions: %v", err)
	}

	// Restore permissions after test
	defer func() {
		os.Chmod(configPath, 0644)
	}()

	cm := &ConfigManager{
		configPath: configPath,
	}

	err = cm.loadConfig()
	if err == nil {
		t.Error("Expected error when config file is not readable")
	}
}

func TestConfigManager_ConfigPath(t *testing.T) {
	configData := `
server:
  port: 7233
  host: "0.0.0.0"
targets: []
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to create ConfigManager: %v", err)
	}

	if cm.configPath != configPath {
		t.Errorf("Expected configPath to be %s, got %s", configPath, cm.configPath)
	}
}

func TestConfigManager_LastLoadTime(t *testing.T) {
	configData := `
server:
  port: 7233
  host: "0.0.0.0"
targets: []
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	beforeCreate := time.Now()
	cm, err := NewConfigManager(configPath)
	afterCreate := time.Now()

	if err != nil {
		t.Fatalf("Failed to create ConfigManager: %v", err)
	}

	// Verify lastLoadTime is within expected range
	if cm.lastLoadTime.Before(beforeCreate) || cm.lastLoadTime.After(afterCreate) {
		t.Errorf("Expected lastLoadTime to be between %v and %v, got %v",
			beforeCreate, afterCreate, cm.lastLoadTime)
	}
}

// Benchmark tests
func BenchmarkConfigManager_GetConfig(b *testing.B) {
	configData := `
server:
  port: 7233
  host: "0.0.0.0"
targets:
  - proxy_id: "bench.internal"
    target: "bench.external:7233"
    tls:
      cert_file: "/bench.crt"
      key_file: "/bench.key"
    encryption_key: "bench-key"
    namespace: "bench-namespace"
`

	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		b.Fatalf("Failed to create test config file: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		b.Fatalf("Failed to create ConfigManager: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			config := cm.GetConfig()
			if config == nil {
				b.Error("GetConfig returned nil")
			}
		}
	})
}

func BenchmarkConfigManager_NewConfigManager(b *testing.B) {
	configData := `
server:
  port: 7233
  host: "0.0.0.0"
targets:
  - proxy_id: "bench.internal"
    target: "bench.external:7233"
    tls:
      cert_file: "/bench.crt"
      key_file: "/bench.key"
    encryption_key: "bench-key"
    namespace: "bench-namespace"
`

	tmpDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		configPath := filepath.Join(tmpDir, fmt.Sprintf("config-%d.yaml", i))

		err := os.WriteFile(configPath, []byte(configData), 0644)
		if err != nil {
			b.Fatalf("Failed to create test config file: %v", err)
		}

		cm, err := NewConfigManager(configPath)
		if err != nil {
			b.Fatalf("Failed to create ConfigManager: %v", err)
		}

		_ = cm.Close()
	}
}
