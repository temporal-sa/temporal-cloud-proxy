package utils

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig   `yaml:"server"`
	Targets []TargetConfig `yaml:"targets"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`
}

type TargetConfig struct {
	Source        string    `yaml:"source"`
	Target        string    `yaml:"target"`
	TLS           TLSConfig `yaml:"tls"`
	EncryptionKey string    `yaml:"encryption_key"`
	Namespace     string    `yaml:"namespace"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

func LoadConfig(configFilePath string) (*Config, error) {
	configFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err = yaml.Unmarshal(configFile, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
