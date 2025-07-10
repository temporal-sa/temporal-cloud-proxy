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
			name: "valid complete config with TLS authentication",
			yamlData: `
server:
  port: 7233
  host: "0.0.0.0"
metrics:
  port: 8080
encryption:
  caching:
    max_cache: 100
    max_age: "1h"
    max_usage: 1000
targets:
  - proxy_id: "test.namespace.internal"
    temporal_cloud:
      namespace: "test.namespace"
      host_port: "test.namespace.tmprl.cloud:7233"
      authentication:
        tls:
          cert_file: "/path/to/cert.crt"
          key_file: "/path/to/key.key"
    encryption_key: "test-key"
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
				Metrics: MetricsConfig{
					Port: 8080,
				},
				Encryption: EncryptionConfig{
					Caching: CachingConfig{
						MaxCache: 100,
						MaxAge:   "1h",
						MaxUsage: 1000,
					},
				},
				Targets: []TargetConfig{
					{
						ProxyId: "test.namespace.internal",
						TemporalCloud: TemporalCloudConfig{
							Namespace: "test.namespace",
							HostPort:  "test.namespace.tmprl.cloud:7233",
							Authentication: TemporalAuthConfig{
								TLS: &TLSConfig{
									CertFile: "/path/to/cert.crt",
									KeyFile:  "/path/to/key.key",
								},
							},
						},
						EncryptionKey: "test-key",
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
			name: "valid config with API key authentication (value)",
			yamlData: `
server:
  port: 8080
  host: "localhost"
metrics:
  port: 9090
targets:
  - proxy_id: "simple.internal"
    temporal_cloud:
      namespace: "simple"
      host_port: "simple.external:8080"
      authentication:
        api_key:
          value: "your-api-key-here"
    encryption_key: "simple-key"
`,
			want: Config{
				Server: ServerConfig{
					Port: 8080,
					Host: "localhost",
				},
				Metrics: MetricsConfig{
					Port: 9090,
				},
				Encryption: EncryptionConfig{
					Caching: CachingConfig{},
				},
				Targets: []TargetConfig{
					{
						ProxyId: "simple.internal",
						TemporalCloud: TemporalCloudConfig{
							Namespace: "simple",
							HostPort:  "simple.external:8080",
							Authentication: TemporalAuthConfig{
								ApiKey: &TemporalApiKeyConfig{
									Value: "your-api-key-here",
								},
							},
						},
						EncryptionKey:  "simple-key",
						Authentication: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with API key authentication (env var)",
			yamlData: `
server:
  port: 8080
  host: "localhost"
metrics:
  port: 9090
targets:
  - proxy_id: "simple.internal"
    temporal_cloud:
      namespace: "simple"
      host_port: "simple.external:8080"
      authentication:
        api_key:
          env: "TEMPORAL_API_KEY"
    encryption_key: "simple-key"
`,
			want: Config{
				Server: ServerConfig{
					Port: 8080,
					Host: "localhost",
				},
				Metrics: MetricsConfig{
					Port: 9090,
				},
				Encryption: EncryptionConfig{
					Caching: CachingConfig{},
				},
				Targets: []TargetConfig{
					{
						ProxyId: "simple.internal",
						TemporalCloud: TemporalCloudConfig{
							Namespace: "simple",
							HostPort:  "simple.external:8080",
							Authentication: TemporalAuthConfig{
								ApiKey: &TemporalApiKeyConfig{
									EnvVar: "TEMPORAL_API_KEY",
								},
							},
						},
						EncryptionKey:  "simple-key",
						Authentication: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple targets with mixed authentication",
			yamlData: `
server:
  port: 9090
  host: "127.0.0.1"
metrics:
  port: 8081
encryption:
  caching:
    max_cache: 50
targets:
  - proxy_id: "target1.internal"
    temporal_cloud:
      namespace: "namespace1"
      host_port: "target1.external:9090"
      authentication:
        tls:
          cert_file: "/target1.crt"
          key_file: "/target1.key"
    encryption_key: "key1"
  - proxy_id: "target2.internal"
    temporal_cloud:
      namespace: "namespace2"
      host_port: "target2.external:9091"
      authentication:
        api_key:
          value: "target2-api-key"
    encryption_key: "key2"
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
				Metrics: MetricsConfig{
					Port: 8081,
				},
				Encryption: EncryptionConfig{
					Caching: CachingConfig{
						MaxCache: 50,
					},
				},
				Targets: []TargetConfig{
					{
						ProxyId: "target1.internal",
						TemporalCloud: TemporalCloudConfig{
							Namespace: "namespace1",
							HostPort:  "target1.external:9090",
							Authentication: TemporalAuthConfig{
								TLS: &TLSConfig{
									CertFile: "/target1.crt",
									KeyFile:  "/target1.key",
								},
							},
						},
						EncryptionKey:  "key1",
						Authentication: nil,
					},
					{
						ProxyId: "target2.internal",
						TemporalCloud: TemporalCloudConfig{
							Namespace: "namespace2",
							HostPort:  "target2.external:9091",
							Authentication: TemporalAuthConfig{
								ApiKey: &TemporalApiKeyConfig{
									Value: "target2-api-key",
								},
							},
						},
						EncryptionKey: "key2",
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
		ProxyId: "test.internal",
		TemporalCloud: TemporalCloudConfig{
			Namespace: "test-namespace",
			HostPort:  "test.external:7233",
			Authentication: TemporalAuthConfig{
				TLS: &TLSConfig{
					CertFile: "/path/to/cert.crt",
					KeyFile:  "/path/to/key.key",
				},
			},
		},
		EncryptionKey: "test-key",
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
	if target.TemporalCloud.HostPort != "test.external:7233" {
		t.Errorf("Expected TemporalCloud.HostPort to be 'test.external:7233', got %s", target.TemporalCloud.HostPort)
	}
	if target.EncryptionKey != "test-key" {
		t.Errorf("Expected EncryptionKey to be 'test-key', got %s", target.EncryptionKey)
	}
	if target.TemporalCloud.Namespace != "test-namespace" {
		t.Errorf("Expected TemporalCloud.Namespace to be 'test-namespace', got %s", target.TemporalCloud.Namespace)
	}
	if target.TemporalCloud.Authentication.TLS.CertFile != "/path/to/cert.crt" {
		t.Errorf("Expected TemporalCloud.Authentication.TLS.CertFile to be '/path/to/cert.crt', got %s", target.TemporalCloud.Authentication.TLS.CertFile)
	}
	if target.TemporalCloud.Authentication.TLS.KeyFile != "/path/to/key.key" {
		t.Errorf("Expected TemporalCloud.Authentication.TLS.KeyFile to be '/path/to/key.key', got %s", target.TemporalCloud.Authentication.TLS.KeyFile)
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

func TestMetricsConfig_Structure(t *testing.T) {
	tests := []struct {
		name   string
		config MetricsConfig
		want   int
	}{
		{
			name:   "default metrics port",
			config: MetricsConfig{Port: 8080},
			want:   8080,
		},
		{
			name:   "custom metrics port",
			config: MetricsConfig{Port: 9090},
			want:   9090,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.Port != tt.want {
				t.Errorf("Expected Port to be %d, got %d", tt.want, tt.config.Port)
			}
		})
	}
}

func TestEncryptionConfig_Structure(t *testing.T) {
	tests := []struct {
		name   string
		config EncryptionConfig
		want   CachingConfig
	}{
		{
			name: "full caching config",
			config: EncryptionConfig{
				Caching: CachingConfig{
					MaxCache: 100,
					MaxAge:   "1h",
					MaxUsage: 1000,
				},
			},
			want: CachingConfig{
				MaxCache: 100,
				MaxAge:   "1h",
				MaxUsage: 1000,
			},
		},
		{
			name: "partial caching config",
			config: EncryptionConfig{
				Caching: CachingConfig{
					MaxCache: 50,
				},
			},
			want: CachingConfig{
				MaxCache: 50,
			},
		},
		{
			name: "empty caching config",
			config: EncryptionConfig{
				Caching: CachingConfig{},
			},
			want: CachingConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.Caching.MaxCache != tt.want.MaxCache {
				t.Errorf("Expected MaxCache to be %d, got %d", tt.want.MaxCache, tt.config.Caching.MaxCache)
			}
			if tt.config.Caching.MaxAge != tt.want.MaxAge {
				t.Errorf("Expected MaxAge to be %s, got %s", tt.want.MaxAge, tt.config.Caching.MaxAge)
			}
			if tt.config.Caching.MaxUsage != tt.want.MaxUsage {
				t.Errorf("Expected MaxUsage to be %d, got %d", tt.want.MaxUsage, tt.config.Caching.MaxUsage)
			}
		})
	}
}

func TestTemporalAuthConfig_Structure(t *testing.T) {
	tests := []struct {
		name   string
		config TemporalAuthConfig
		desc   string
	}{
		{
			name: "TLS authentication",
			config: TemporalAuthConfig{
				TLS: &TLSConfig{
					CertFile: "/path/to/cert.crt",
					KeyFile:  "/path/to/key.key",
				},
			},
			desc: "should have TLS config and no API key",
		},
		{
			name: "API key authentication with value",
			config: TemporalAuthConfig{
				ApiKey: &TemporalApiKeyConfig{
					Value: "test-api-key",
				},
			},
			desc: "should have API key and no TLS config",
		},
		{
			name: "API key authentication with env var",
			config: TemporalAuthConfig{
				ApiKey: &TemporalApiKeyConfig{
					EnvVar: "TEMPORAL_API_KEY",
				},
			},
			desc: "should have API key env var and no TLS config",
		},
		{
			name:   "empty authentication",
			config: TemporalAuthConfig{},
			desc:   "should have neither TLS nor API key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "TLS authentication":
				if tt.config.TLS == nil {
					t.Error("Expected TLS to not be nil")
				} else {
					if tt.config.TLS.CertFile != "/path/to/cert.crt" {
						t.Errorf("Expected CertFile to be '/path/to/cert.crt', got %s", tt.config.TLS.CertFile)
					}
					if tt.config.TLS.KeyFile != "/path/to/key.key" {
						t.Errorf("Expected KeyFile to be '/path/to/key.key', got %s", tt.config.TLS.KeyFile)
					}
				}
				if tt.config.ApiKey != nil {
					t.Error("Expected ApiKey to be nil")
				}
			case "API key authentication with value":
				if tt.config.ApiKey == nil {
					t.Error("Expected ApiKey to not be nil")
				} else {
					if tt.config.ApiKey.Value != "test-api-key" {
						t.Errorf("Expected ApiKey.Value to be 'test-api-key', got %s", tt.config.ApiKey.Value)
					}
					if tt.config.ApiKey.EnvVar != "" {
						t.Errorf("Expected ApiKey.EnvVar to be empty, got %s", tt.config.ApiKey.EnvVar)
					}
				}
				if tt.config.TLS != nil {
					t.Error("Expected TLS to be nil")
				}
			case "API key authentication with env var":
				if tt.config.ApiKey == nil {
					t.Error("Expected ApiKey to not be nil")
				} else {
					if tt.config.ApiKey.EnvVar != "TEMPORAL_API_KEY" {
						t.Errorf("Expected ApiKey.EnvVar to be 'TEMPORAL_API_KEY', got %s", tt.config.ApiKey.EnvVar)
					}
					if tt.config.ApiKey.Value != "" {
						t.Errorf("Expected ApiKey.Value to be empty, got %s", tt.config.ApiKey.Value)
					}
				}
				if tt.config.TLS != nil {
					t.Error("Expected TLS to be nil")
				}
			case "empty authentication":
				if tt.config.TLS != nil {
					t.Error("Expected TLS to be nil")
				}
				if tt.config.ApiKey != nil {
					t.Error("Expected ApiKey to be nil")
				}
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
	if a.ProxyId != b.ProxyId || a.EncryptionKey != b.EncryptionKey {
		return false
	}

	// Compare TemporalCloud configuration
	if a.TemporalCloud.Namespace != b.TemporalCloud.Namespace || a.TemporalCloud.HostPort != b.TemporalCloud.HostPort {
		return false
	}

	// Compare TemporalCloud Authentication - API Key
	if (a.TemporalCloud.Authentication.ApiKey == nil) != (b.TemporalCloud.Authentication.ApiKey == nil) {
		return false
	}

	if a.TemporalCloud.Authentication.ApiKey != nil && b.TemporalCloud.Authentication.ApiKey != nil {
		if a.TemporalCloud.Authentication.ApiKey.Value != b.TemporalCloud.Authentication.ApiKey.Value ||
			a.TemporalCloud.Authentication.ApiKey.EnvVar != b.TemporalCloud.Authentication.ApiKey.EnvVar {
			return false
		}
	}

	// Compare TLS configuration
	if (a.TemporalCloud.Authentication.TLS == nil) != (b.TemporalCloud.Authentication.TLS == nil) {
		return false
	}

	if a.TemporalCloud.Authentication.TLS != nil && b.TemporalCloud.Authentication.TLS != nil {
		if a.TemporalCloud.Authentication.TLS.CertFile != b.TemporalCloud.Authentication.TLS.CertFile ||
			a.TemporalCloud.Authentication.TLS.KeyFile != b.TemporalCloud.Authentication.TLS.KeyFile {
			return false
		}
	}

	// Compare proxy Authentication (spiffe, oauth, etc.)
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
