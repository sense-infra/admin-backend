package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Auth     AuthConfig     `json:"auth"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port string `json:"port"`
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
	SSLMode  string `json:"sslmode"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	APIKeys []string `json:"api_keys"`
}

// Load loads configuration from environment variables or config file
func Load() *Config {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnv("SERVER_PORT", ":8080"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvAsInt("DB_PORT", 3306),
			User:     getEnv("DB_USER", "sense_user"),
			Password: getEnv("DB_PASSWORD", ""),
			Database: getEnv("DB_NAME", "sense_security"),
			SSLMode:  getEnv("DB_SSLMODE", "preferred"),
		},
		Auth: AuthConfig{
			APIKeys: getAPIKeys(),
		},
	}

	// Try to load from config file if exists
	if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
		if err := loadFromFile(configFile, cfg); err != nil {
			log.Printf("Warning: Failed to load config file %s: %v", configFile, err)
		}
	}

	return cfg
}

// DSN returns the database connection string
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=Local&tls=%s",
		d.User, d.Password, d.Host, d.Port, d.Database, d.SSLMode)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getAPIKeys() []string {
	// API keys can be provided as comma-separated list in env var
	if keys := os.Getenv("API_KEYS"); keys != "" {
		return strings.Split(keys, ",")
	}
	
	// Or load from a file
	if keyFile := os.Getenv("API_KEY_FILE"); keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			log.Printf("Warning: Failed to read API key file: %v", err)
			return []string{}
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
	
	return []string{}
}

func loadFromFile(filename string, cfg *Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, cfg)
}
