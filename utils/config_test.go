package utils

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfig_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		yamlData string
		want     Config
		wantErr  bool
	}{
		{
			name: "valid complete config",
			yamlData: `
server:
  port: 7233
  host: "0.0.0.0"
targets:
  - proxy_id: "test.namespace.internal"
    target: "test.namespace.tmprl.cloud:7233"
    tls:
      cert_file: "/path/to/cert.crt"
      key_file: "/path/to/key.key"
    encryption_key: "test-key"
    namespace: "test.namespace"
    authentication:
      type: "spiffe"
      config:
        trust_domain: "spiffe://example.org/"
        endpoint: "unix:///tmp/spire-agent/public/api.sock"
        audiences:
          - "test_audience"
`,
			want: Config{
				Server: ServerConfig{
					Port: 7233,
					Host: "0.0.0.0",
				},
				Targets: []TargetConfig{
					{
						ProxyId:       "test.namespace.internal",
						Target:        "test.namespace.tmprl.cloud:7233",
						EncryptionKey: "test-key",
						Namespace:     "test.namespace",
						TLS: TLSConfig{
							CertFile: "/path/to/cert.crt",
							KeyFile:  "/path/to/key.key",
						},
						Authentication: &AuthConfig{
							Type: "spiffe",
							Config: map[string]interface{}{
								"trust_domain": "spiffe://example.org/",
								"endpoint":     "unix:///tmp/spire-agent/public/api.sock",
								"audiences":    []interface{}{"test_audience"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "minimal config without authentication",
			yamlData: `
server:
  port: 8080
  host: "localhost"
targets:
  - proxy_id: "simple.internal"
    target: "simple.external:8080"
    tls:
      cert_file: "/cert.crt"
      key_file: "/key.key"
    encryption_key: "simple-key"
    namespace: "simple"
`,
			want: Config{
				Server: ServerConfig{
					Port: 8080,
					Host: "localhost",
				},
				Targets: []TargetConfig{
					{
						ProxyId:       "simple.internal",
						Target:        "simple.external:8080",
						EncryptionKey: "simple-key",
						Namespace:     "simple",
						TLS: TLSConfig{
							CertFile: "/cert.crt",
							KeyFile:  "/key.key",
						},
						Authentication: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple targets",
			yamlData: `
server:
  port: 9090
  host: "127.0.0.1"
targets:
  - proxy_id: "target1.internal"
    target: "target1.external:9090"
    tls:
      cert_file: "/target1.crt"
      key_file: "/target1.key"
    encryption_key: "key1"
    namespace: "namespace1"
  - proxy_id: "target2.internal"
    target: "target2.external:9091"
    tls:
      cert_file: "/target2.crt"
      key_file: "/target2.key"
    encryption_key: "key2"
    namespace: "namespace2"
    authentication:
      type: "oauth"
      config:
        client_id: "test-client"
        client_secret: "test-secret"
`,
			want: Config{
				Server: ServerConfig{
					Port: 9090,
					Host: "127.0.0.1",
				},
				Targets: []TargetConfig{
					{
						ProxyId:       "target1.internal",
						Target:        "target1.external:9090",
						EncryptionKey: "key1",
						Namespace:     "namespace1",
						TLS: TLSConfig{
							CertFile: "/target1.crt",
							KeyFile:  "/target1.key",
						},
						Authentication: nil,
					},
					{
						ProxyId:       "target2.internal",
						Target:        "target2.external:9091",
						EncryptionKey: "key2",
						Namespace:     "namespace2",
						TLS: TLSConfig{
							CertFile: "/target2.crt",
							KeyFile:  "/target2.key",
						},
						Authentication: &AuthConfig{
							Type: "oauth",
							Config: map[string]interface{}{
								"client_id":     "test-client",
								"client_secret": "test-secret",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "invalid yaml",
			yamlData: `invalid: yaml: content: [`,
			want:     Config{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Config
			err := yaml.Unmarshal([]byte(tt.yamlData), &got)

			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if !configEqual(got, tt.want) {
					t.Errorf("yaml.Unmarshal() got = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func TestServerConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config ServerConfig
		valid  bool
	}{
		{
			name: "valid server config",
			config: ServerConfig{
				Port: 7233,
				Host: "0.0.0.0",
			},
			valid: true,
		},
		{
			name: "valid localhost config",
			config: ServerConfig{
				Port: 8080,
				Host: "localhost",
			},
			valid: true,
		},
		{
			name: "zero port should be handled by application logic",
			config: ServerConfig{
				Port: 0,
				Host: "localhost",
			},
			valid: true, // Structure is valid, business logic should handle port validation
		},
		{
			name: "empty host should be handled by application logic",
			config: ServerConfig{
				Port: 8080,
				Host: "",
			},
			valid: true, // Structure is valid, business logic should handle host validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since there's no validation method in the struct, we just test that the struct can be created
			// In a real application, you might have validation methods
			if tt.config.Port < 0 || tt.config.Port > 65535 {
				t.Errorf("Port %d is outside valid range", tt.config.Port)
			}
		})
	}
}

func TestTargetConfig_Structure(t *testing.T) {
	target := TargetConfig{
		ProxyId:       "test.internal",
		Target:        "test.external:7233",
		EncryptionKey: "test-key",
		Namespace:     "test-namespace",
		TLS: TLSConfig{
			CertFile: "/path/to/cert.crt",
			KeyFile:  "/path/to/key.key",
		},
		Authentication: &AuthConfig{
			Type: "spiffe",
			Config: map[string]interface{}{
				"trust_domain": "spiffe://example.org/",
			},
		},
	}

	if target.ProxyId != "test.internal" {
		t.Errorf("Expected ProxyId to be 'test.internal', got %s", target.ProxyId)
	}
	if target.Target != "test.external:7233" {
		t.Errorf("Expected Target to be 'test.external:7233', got %s", target.Target)
	}
	if target.EncryptionKey != "test-key" {
		t.Errorf("Expected EncryptionKey to be 'test-key', got %s", target.EncryptionKey)
	}
	if target.Namespace != "test-namespace" {
		t.Errorf("Expected Namespace to be 'test-namespace', got %s", target.Namespace)
	}
	if target.TLS.CertFile != "/path/to/cert.crt" {
		t.Errorf("Expected TLS.CertFile to be '/path/to/cert.crt', got %s", target.TLS.CertFile)
	}
	if target.TLS.KeyFile != "/path/to/key.key" {
		t.Errorf("Expected TLS.KeyFile to be '/path/to/key.key', got %s", target.TLS.KeyFile)
	}
	if target.Authentication == nil {
		t.Error("Expected Authentication to not be nil")
	} else {
		if target.Authentication.Type != "spiffe" {
			t.Errorf("Expected Authentication.Type to be 'spiffe', got %s", target.Authentication.Type)
		}
		if trustDomain, ok := target.Authentication.Config["trust_domain"]; !ok || trustDomain != "spiffe://example.org/" {
			t.Errorf("Expected trust_domain to be 'spiffe://example.org/', got %v", trustDomain)
		}
	}
}

func TestAuthConfig_Types(t *testing.T) {
	tests := []struct {
		name       string
		authConfig AuthConfig
		wantType   string
	}{
		{
			name: "spiffe auth",
			authConfig: AuthConfig{
				Type: "spiffe",
				Config: map[string]interface{}{
					"trust_domain": "spiffe://example.org/",
					"endpoint":     "unix:///tmp/spire-agent/public/api.sock",
				},
			},
			wantType: "spiffe",
		},
		{
			name: "oauth auth",
			authConfig: AuthConfig{
				Type: "oauth",
				Config: map[string]interface{}{
					"client_id":     "test-client",
					"client_secret": "test-secret",
				},
			},
			wantType: "oauth",
		},
		{
			name: "custom auth",
			authConfig: AuthConfig{
				Type: "custom",
				Config: map[string]interface{}{
					"custom_field": "custom_value",
				},
			},
			wantType: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.authConfig.Type != tt.wantType {
				t.Errorf("Expected Type to be %s, got %s", tt.wantType, tt.authConfig.Type)
			}
			if tt.authConfig.Config == nil {
				t.Error("Expected Config to not be nil")
			}
		})
	}
}

// Helper function to compare Config structs
func configEqual(a, b Config) bool {
	if a.Server.Port != b.Server.Port || a.Server.Host != b.Server.Host {
		return false
	}

	if len(a.Targets) != len(b.Targets) {
		return false
	}

	for i, targetA := range a.Targets {
		targetB := b.Targets[i]
		if !targetConfigEqual(targetA, targetB) {
			return false
		}
	}

	return true
}

func targetConfigEqual(a, b TargetConfig) bool {
	if a.ProxyId != b.ProxyId || a.Target != b.Target || a.EncryptionKey != b.EncryptionKey || a.Namespace != b.Namespace {
		return false
	}

	if a.TLS.CertFile != b.TLS.CertFile || a.TLS.KeyFile != b.TLS.KeyFile {
		return false
	}

	if (a.Authentication == nil) != (b.Authentication == nil) {
		return false
	}

	if a.Authentication != nil && b.Authentication != nil {
		if a.Authentication.Type != b.Authentication.Type {
			return false
		}
		if len(a.Authentication.Config) != len(b.Authentication.Config) {
			return false
		}
		// Simple comparison - in production you might want more sophisticated comparison
		for key, valueA := range a.Authentication.Config {
			if valueB, exists := b.Authentication.Config[key]; !exists {
				return false
			} else {
				// Handle slice comparison for audiences
				if sliceA, okA := valueA.([]interface{}); okA {
					if sliceB, okB := valueB.([]interface{}); okB {
						if len(sliceA) != len(sliceB) {
							return false
						}
						for j, itemA := range sliceA {
							if itemA != sliceB[j] {
								return false
							}
						}
					} else {
						return false
					}
				} else if valueA != valueB {
					return false
				}
			}
		}
	}

	return true
}
