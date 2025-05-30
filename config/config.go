package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Security SecurityConfig
}

type ServerConfig struct {
	Port        string
	Environment string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

type JWTConfig struct {
	Secret string
}

type SecurityConfig struct {
	SessionTimeout     int  // in hours
	MaxFailedLogins    int
	AccountLockTime    int  // in minutes
	RequireHTTPS       bool
	CSRFProtection     bool
	RateLimitEnabled   bool
	RateLimitRequests  int  // requests per minute
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:        getEnv("SERVER_PORT", "8080"),
			Environment: getEnv("ENVIRONMENT", "development"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "dev-mariadb-ms.dev"),
			Port:     getEnv("DB_PORT", "3306"),
			User:     getEnv("DB_USER", "admin"),
			Password: getEnv("DB_PASSWORD", "changeme"),
			Name:     getEnv("DB_NAME", "dev"),
			SSLMode:  getEnv("DB_SSLMODE", "false"),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", generateDefaultJWTSecret()),
		},
		Security: SecurityConfig{
			SessionTimeout:     getEnvAsInt("SESSION_TIMEOUT_HOURS", 24),
			MaxFailedLogins:    getEnvAsInt("MAX_FAILED_LOGINS", 5),
			AccountLockTime:    getEnvAsInt("ACCOUNT_LOCK_TIME_MINUTES", 30),
			RequireHTTPS:       getEnvAsBool("REQUIRE_HTTPS", false),
			CSRFProtection:     getEnvAsBool("CSRF_PROTECTION", true),
			RateLimitEnabled:   getEnvAsBool("RATE_LIMIT_ENABLED", true),
			RateLimitRequests:  getEnvAsInt("RATE_LIMIT_REQUESTS_PER_MINUTE", 60),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func generateDefaultJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("WARNING: Using default JWT secret. Set JWT_SECRET environment variable for production!")
		return "senseguard_default_jwt_secret_change_in_production"
	}
	return secret
}

// GetDSN returns the database connection string
func (d *DatabaseConfig) GetDSN() string {
	return d.User + ":" + d.Password + "@tcp(" + d.Host + ":" + d.Port + ")/" + d.Name + "?parseTime=true"
}
