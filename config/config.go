package config

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
	"os"
)

const (
	ConfigPathFlag    = "config"
	DefaultConfigPath = "config.yaml"
	LogLevelFlag      = "level"
)

type (
	ConfigProvider interface {
		GetProxyConfig() ProxyConfig
	}

	ProxyConfig struct {
		Server     ServerConfig     `yaml:"server"`
		Metrics    MetricsConfig    `yaml:"metrics"`
		Encryption EncryptionConfig `yaml:"encryption"`
		Workloads  []WorkloadConfig `yaml:"workloads"`
	}

	ServerConfig struct {
		Port int    `yaml:"port"`
		Host string `yaml:"host"`
	}

	MetricsConfig struct {
		Port int `yaml:"port"`
	}

	EncryptionConfig struct {
		Caching CachingConfig `yaml:"caching"`
	}

	CachingConfig struct {
		MaxCache int    `yaml:"max_cache,omitempty"`
		MaxAge   string `yaml:"max_age,omitempty"`
		MaxUsage int    `yaml:"max_usage,omitempty"`
	}

	WorkloadConfig struct {
		WorkloadId     string              `yaml:"workload_id"`
		TemporalCloud  TemporalCloudConfig `yaml:"temporal_cloud"`
		EncryptionKey  string              `yaml:"encryption_key"`
		Authentication *AuthConfig         `yaml:"authentication,omitempty"`
	}

	TemporalCloudConfig struct {
		Namespace      string             `yaml:"namespace"`
		HostPort       string             `yaml:"host_port"`
		Authentication TemporalAuthConfig `yaml:"authentication"`
	}

	TemporalAuthConfig struct {
		TLS    *TLSConfig            `yaml:"tls,omitempty"`
		ApiKey *TemporalApiKeyConfig `yaml:"api_key,omitempty"`
	}

	TemporalApiKeyConfig struct {
		Value  string `yaml:"value,omitempty"`
		EnvVar string `yaml:"env,omitempty"`
	}

	TLSConfig struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	}

	AuthConfig struct {
		Type   string                 `yaml:"type"`
		Config map[string]interface{} `yaml:"config"`
	}

	cliConfigProvider struct {
		ctx         *cli.Context
		proxyConfig ProxyConfig
	}
)

func newConfigProvider(ctx *cli.Context) (ConfigProvider, error) {
	proxyConfig, err := LoadConfig(ctx.String(ConfigPathFlag))
	if err != nil {
		return nil, err
	}

	return &cliConfigProvider{
		ctx:         ctx,
		proxyConfig: proxyConfig,
	}, nil
}

func (c *cliConfigProvider) GetProxyConfig() ProxyConfig {
	return c.proxyConfig
}

func LoadConfig(configFilePath string) (ProxyConfig, error) {
	var config ProxyConfig

	configFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	if err = yaml.Unmarshal(configFile, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return config, nil
}
