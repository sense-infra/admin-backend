#!/bin/bash

echo "Creating all code files..."

# Create main.go
cat > main.go << 'MAINFILE'
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/config"
	"github.com/sense-security/api/db"
	"github.com/sense-security/api/handlers"
	"github.com/sense-security/api/middleware"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	database, err := db.Initialize(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Create router
	router := mux.NewRouter()

	// Apply middleware
	router.Use(middleware.Logger)
	router.Use(middleware.CORS)
	router.Use(middleware.ContentType)

	// Initialize handlers
	h := handlers.New(database)

	// Health check endpoint (no auth required)
	router.HandleFunc("/health", h.HealthCheck).Methods("GET")
	router.HandleFunc("/ready", h.ReadinessCheck).Methods("GET")

	// API routes with authentication
	api := router.PathPrefix("/api").Subrouter()
	api.Use(middleware.APIKeyAuth(cfg.Auth.APIKeys))

	// Customer routes
	api.HandleFunc("/customers", h.ListCustomers).Methods("GET")
	api.HandleFunc("/customers", h.CreateCustomer).Methods("POST")
	api.HandleFunc("/customers/{id}", h.GetCustomer).Methods("GET")
	api.HandleFunc("/customers/{id}", h.UpdateCustomer).Methods("PUT")
	api.HandleFunc("/customers/{id}", h.DeleteCustomer).Methods("DELETE")

	// Contract routes
	api.HandleFunc("/contracts", h.ListContracts).Methods("GET")
	api.HandleFunc("/contracts", h.CreateContract).Methods("POST")
	api.HandleFunc("/contracts/{id}", h.GetContract).Methods("GET")
	api.HandleFunc("/contracts/{id}", h.UpdateContract).Methods("PUT")
	api.HandleFunc("/contracts/{id}", h.DeleteContract).Methods("DELETE")
	api.HandleFunc("/contracts/{id}/customers", h.ListContractCustomers).Methods("GET")
	api.HandleFunc("/contracts/{id}/customers/{customerId}", h.AddCustomerToContract).Methods("POST")
	api.HandleFunc("/contracts/{id}/customers/{customerId}", h.RemoveCustomerFromContract).Methods("DELETE")

	// Service Tier routes
	api.HandleFunc("/service-tiers", h.ListServiceTiers).Methods("GET")
	api.HandleFunc("/service-tiers", h.CreateServiceTier).Methods("POST")
	api.HandleFunc("/service-tiers/{id}", h.GetServiceTier).Methods("GET")
	api.HandleFunc("/service-tiers/{id}", h.UpdateServiceTier).Methods("PUT")
	api.HandleFunc("/service-tiers/{id}", h.DeleteServiceTier).Methods("DELETE")

	// Contract Service Tier assignment
	api.HandleFunc("/contracts/{id}/service-tier", h.AssignServiceTier).Methods("POST")
	api.HandleFunc("/contracts/{id}/service-tier/current", h.GetCurrentServiceTier).Methods("GET")

	// NVR routes
	api.HandleFunc("/nvr-profiles", h.ListNVRProfiles).Methods("GET")
	api.HandleFunc("/nvr-profiles", h.CreateNVRProfile).Methods("POST")
	api.HandleFunc("/nvr-profiles/{id}", h.GetNVRProfile).Methods("GET")
	api.HandleFunc("/nvr-profiles/{id}", h.UpdateNVRProfile).Methods("PUT")
	api.HandleFunc("/nvr-profiles/{id}", h.DeleteNVRProfile).Methods("DELETE")

	api.HandleFunc("/nvrs", h.ListNVRs).Methods("GET")
	api.HandleFunc("/nvrs", h.CreateNVR).Methods("POST")
	api.HandleFunc("/nvrs/{id}", h.GetNVR).Methods("GET")
	api.HandleFunc("/nvrs/{id}", h.UpdateNVR).Methods("PUT")
	api.HandleFunc("/nvrs/{id}", h.DeleteNVR).Methods("DELETE")

	// Camera routes
	api.HandleFunc("/cameras", h.ListCameras).Methods("GET")
	api.HandleFunc("/cameras", h.CreateCamera).Methods("POST")
	api.HandleFunc("/cameras/{id}", h.GetCamera).Methods("GET")
	api.HandleFunc("/cameras/{id}", h.UpdateCamera).Methods("PUT")
	api.HandleFunc("/cameras/{id}", h.DeleteCamera).Methods("DELETE")

	// Controller routes
	api.HandleFunc("/controllers", h.ListControllers).Methods("GET")
	api.HandleFunc("/controllers", h.CreateController).Methods("POST")
	api.HandleFunc("/controllers/{id}", h.GetController).Methods("GET")
	api.HandleFunc("/controllers/{id}", h.UpdateController).Methods("PUT")
	api.HandleFunc("/controllers/{id}", h.DeleteController).Methods("DELETE")

	// TPM Device routes
	api.HandleFunc("/tpm-devices", h.ListTPMDevices).Methods("GET")
	api.HandleFunc("/tpm-devices", h.CreateTPMDevice).Methods("POST")
	api.HandleFunc("/tpm-devices/{id}", h.GetTPMDevice).Methods("GET")
	api.HandleFunc("/tpm-devices/{id}", h.UpdateTPMDevice).Methods("PUT")
	api.HandleFunc("/tpm-devices/{id}", h.DeleteTPMDevice).Methods("DELETE")

	// VPN Config routes
	api.HandleFunc("/vpn-configs", h.ListVPNConfigs).Methods("GET")
	api.HandleFunc("/vpn-configs", h.CreateVPNConfig).Methods("POST")
	api.HandleFunc("/vpn-configs/{id}", h.GetVPNConfig).Methods("GET")
	api.HandleFunc("/vpn-configs/{id}", h.UpdateVPNConfig).Methods("PUT")
	api.HandleFunc("/vpn-configs/{id}", h.DeleteVPNConfig).Methods("DELETE")

	// RF Frequency routes
	api.HandleFunc("/rf-frequencies", h.ListRFFrequencies).Methods("GET")
	api.HandleFunc("/rf-frequencies", h.CreateRFFrequency).Methods("POST")
	api.HandleFunc("/rf-frequencies/{id}", h.GetRFFrequency).Methods("GET")
	api.HandleFunc("/rf-frequencies/{id}", h.UpdateRFFrequency).Methods("PUT")
	api.HandleFunc("/rf-frequencies/{id}", h.DeleteRFFrequency).Methods("DELETE")

	// Contract RF Monitoring routes
	api.HandleFunc("/contracts/{id}/rf-monitoring", h.ListContractRFMonitoring).Methods("GET")
	api.HandleFunc("/contracts/{id}/rf-monitoring", h.ConfigureRFMonitoring).Methods("POST")
	api.HandleFunc("/contracts/{id}/rf-monitoring/{frequencyId}", h.UpdateRFMonitoring).Methods("PUT")
	api.HandleFunc("/contracts/{id}/rf-monitoring/{frequencyId}", h.DeleteRFMonitoring).Methods("DELETE")

	// Mapping routes
	api.HandleFunc("/contracts/{id}/nvrs", h.ListContractNVRs).Methods("GET")
	api.HandleFunc("/contracts/{id}/nvrs/{nvrId}", h.AddNVRToContract).Methods("POST")
	api.HandleFunc("/contracts/{id}/nvrs/{nvrId}", h.RemoveNVRFromContract).Methods("DELETE")

	api.HandleFunc("/nvrs/{id}/cameras", h.ListNVRCameras).Methods("GET")
	api.HandleFunc("/nvrs/{id}/cameras/{cameraId}", h.AddCameraToNVR).Methods("POST")
	api.HandleFunc("/nvrs/{id}/cameras/{cameraId}", h.RemoveCameraFromNVR).Methods("DELETE")

	api.HandleFunc("/nvrs/{id}/controllers", h.ListNVRControllers).Methods("GET")
	api.HandleFunc("/nvrs/{id}/controllers/{controllerId}", h.AddControllerToNVR).Methods("POST")
	api.HandleFunc("/nvrs/{id}/controllers/{controllerId}", h.RemoveControllerFromNVR).Methods("DELETE")

	api.HandleFunc("/controllers/{id}/cameras", h.ListControllerCameras).Methods("GET")
	api.HandleFunc("/controllers/{id}/cameras/{cameraId}/support", h.AddCameraSupport).Methods("POST")
	api.HandleFunc("/controllers/{id}/cameras/{cameraId}/support", h.RemoveCameraSupport).Methods("DELETE")

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server shutdown complete")
}
MAINFILE

# Create config/config.go
cat > config/config.go << 'CONFIGFILE'
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
CONFIGFILE

# Create db/db.go
cat > db/db.go << 'DBFILE'
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sense-security/api/config"
)

// DB wraps the SQL database connection
type DB struct {
	*sql.DB
}

// Initialize creates and configures the database connection
func Initialize(cfg config.DatabaseConfig) (*DB, error) {
	db, err := sql.Open("mysql", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{db}, nil
}

// Transaction executes a function within a database transaction
func (db *DB) Transaction(fn func(*sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}
DBFILE

# Create middleware/middleware.go
cat > middleware/middleware.go << 'MIDDLEWAREFILE'
package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
)

// Logger middleware logs all requests
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a custom response writer to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(lrw, r)
		
		log.Printf(
			"[%s] %s %s %d %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			lrw.statusCode,
			time.Since(start),
		)
	})
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "3600")
		
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// ContentType middleware sets the content type for all responses
func ContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// APIKeyAuth middleware validates API key authentication
func APIKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	// Create a map for O(1) lookup
	keyMap := make(map[string]bool)
	for _, key := range validKeys {
		keyMap[strings.TrimSpace(key)] = true
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for API key in header
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				// Also check Authorization header with Bearer token
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					apiKey = strings.TrimPrefix(auth, "Bearer ")
				}
			}
			
			// Validate API key
			if apiKey == "" || !keyMap[strings.TrimSpace(apiKey)] {
				http.Error(w, `{"error": "Invalid or missing API key"}`, http.StatusUnauthorized)
				return
			}
			
			// Add API key to context for logging purposes
			ctx := context.WithValue(r.Context(), "api_key", apiKey[:8]+"...") // Only store partial key
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
MIDDLEWAREFILE

# Create models/models.go
cat > models/models.go << 'MODELSFILE'
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Customer represents a customer in the system
type Customer struct {
	CustomerID     int       `json:"customer_id" db:"customer_id"`
	NameOnContract string    `json:"name_on_contract" db:"name_on_contract"`
	Address        string    `json:"address" db:"address"`
	UniqueID       string    `json:"unique_id" db:"unique_id"`
	Email          *string   `json:"email,omitempty" db:"email"`
	PhoneNumber    *string   `json:"phone_number,omitempty" db:"phone_number"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// Contract represents a service contract
type Contract struct {
	ContractID        int       `json:"contract_id" db:"contract_id"`
	ServiceAddress    string    `json:"service_address" db:"service_address"`
	NotificationEmail *string   `json:"notification_email,omitempty" db:"notification_email"`
	NotificationPhone *string   `json:"notification_phone,omitempty" db:"notification_phone"`
	StartDate         time.Time `json:"start_date" db:"start_date"`
	EndDate           time.Time `json:"end_date" db:"end_date"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// ServiceTier represents a service tier
type ServiceTier struct {
	ServiceTierID int             `json:"service_tier_id" db:"service_tier_id"`
	Name          string          `json:"name" db:"name"`
	Description   *string         `json:"description,omitempty" db:"description"`
	Config        json.RawMessage `json:"config,omitempty" db:"config"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`
}

// ContractServiceTier represents a service tier assignment to a contract
type ContractServiceTier struct {
	ContractServiceTierID int       `json:"contract_service_tier_id" db:"contract_service_tier_id"`
	ContractID            int       `json:"contract_id" db:"contract_id"`
	ServiceTierID         int       `json:"service_tier_id" db:"service_tier_id"`
	StartDate             time.Time `json:"start_date" db:"start_date"`
	EndDate               time.Time `json:"end_date" db:"end_date"`
	CreatedAt             time.Time `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time `json:"updated_at" db:"updated_at"`
}

// NVRProfile represents an NVR configuration profile
type NVRProfile struct {
	ProfileID      int             `json:"profile_id" db:"profile_id"`
	Name           string          `json:"name" db:"name"`
	Manufacturer   string          `json:"manufacturer" db:"manufacturer"`
	APIType        string          `json:"api_type" db:"api_type"`
	AuthType       string          `json:"auth_type" db:"auth_type"`
	StreamConfig   json.RawMessage `json:"stream_config" db:"stream_config"`
	EventConfig    json.RawMessage `json:"event_config,omitempty" db:"event_config"`
	RequiredParams json.RawMessage `json:"required_params,omitempty" db:"required_params"`
	CreatedAt      time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at" db:"updated_at"`
}

// NVR represents a Network Video Recorder
type NVR struct {
	NVRID             int       `json:"nvr_id" db:"nvr_id"`
	Model             string    `json:"model" db:"model"`
	SerialNumber      string    `json:"serial_number" db:"serial_number"`
	FirmwareVersion   *string   `json:"firmware_version,omitempty" db:"firmware_version"`
	StorageCapacityGB *int      `json:"storage_capacity_gb,omitempty" db:"storage_capacity_gb"`
	LoginUsername     string    `json:"login_username" db:"login_username"`
	LoginPasswordRef  string    `json:"login_password_ref" db:"login_password_ref"`
	ProfileID         *int      `json:"profile_id,omitempty" db:"profile_id"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// Camera represents a security camera
type Camera struct {
	CameraID           int       `json:"camera_id" db:"camera_id"`
	Name               string    `json:"name" db:"name"`
	ManufacturerUID    string    `json:"manufacturer_uid" db:"manufacturer_uid"`
	Model              string    `json:"model" db:"model"`
	SerialNumber       string    `json:"serial_number" db:"serial_number"`
	Resolution         *string   `json:"resolution,omitempty" db:"resolution"`
	Status             string    `json:"status" db:"status"`
	TalkBackSupport    bool      `json:"talk_back_support" db:"talk_back_support"`
	NightVisionSupport bool      `json:"night_vision_support" db:"night_vision_support"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

// TPMDevice represents a Trusted Platform Module device
type TPMDevice struct {
	TPMDeviceID         int       `json:"tmp_device_id" db:"tmp_device_id"`
	Manufacturer        string    `json:"manufacturer" db:"manufacturer"`
	Model               string    `json:"model" db:"model"`
	SerialNumber        string    `json:"serial_number" db:"serial_number"`
	Version             string    `json:"version" db:"version"`
	Certified           bool      `json:"certified" db:"certified"`
	SupportedAlgorithms *string   `json:"supported_algorithms,omitempty" db:"supported_algorithms"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

// Controller represents a controller device
type Controller struct {
	ControllerID       int       `json:"controller_id" db:"controller_id"`
	Type               string    `json:"type" db:"type"`
	Model              string    `json:"model" db:"model"`
	SerialNumber       string    `json:"serial_number" db:"serial_number"`
	OSArchitecture     string    `json:"os_architecture" db:"os_architecture"`
	HWEncryptionEnabled bool     `json:"hw_encryption_enabled" db:"hw_encryption_enabled"`
	SWEncryptionEnabled bool     `json:"sw_encryption_enabled" db:"sw_encryption_enabled"`
	TPMDeviceID        *int      `json:"tmp_device_id,omitempty" db:"tmp_device_id"`
	FirmwareVersion    *string   `json:"firmware_version,omitempty" db:"firmware_version"`
	ResetPasswordRef   string    `json:"reset_password_ref" db:"reset_password_ref"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

// VPNConfig represents a VPN configuration
type VPNConfig struct {
	VPNID            int             `json:"vpn_id" db:"vpn_id"`
	Name             string          `json:"name" db:"name"`
	ServerPublicKey  string          `json:"server_public_key" db:"server_public_key"`
	ServerEndpoint   string          `json:"server_endpoint" db:"server_endpoint"`
	AllowedIPs       json.RawMessage `json:"allowed_ips" db:"allowed_ips"`
	DNSServers       json.RawMessage `json:"dns_servers,omitempty" db:"dns_servers"`
	DNSSearchDomains json.RawMessage `json:"dns_search_domains,omitempty" db:"dns_search_domains"`
	ConfigRef        *string         `json:"config_ref,omitempty" db:"config_ref"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`
}

// RFFrequencyProfile represents an RF frequency monitoring profile
type RFFrequencyProfile struct {
	FrequencyID         int      `json:"frequency_id" db:"frequency_id"`
	FrequencyMHz        float64  `json:"frequency_mhz" db:"frequency_mhz"`
	FrequencyName       string   `json:"frequency_name" db:"frequency_name"`
	Description         *string  `json:"description,omitempty" db:"description"`
	Category            string   `json:"category" db:"category"`
	DefaultThresholdDBm float64  `json:"default_threshold_dbm" db:"default_threshold_dbm"`
	DefaultEnabled      bool     `json:"default_enabled" db:"default_enabled"`
	BandwidthKHz        *int     `json:"bandwidth_khz,omitempty" db:"bandwidth_khz"`
	ModulationType      *string  `json:"modulation_type,omitempty" db:"modulation_type"`
	TypicalUsage        *string  `json:"typical_usage,omitempty" db:"typical_usage"`
	SecurityImportance  string   `json:"security_importance" db:"security_importance"`
	JammingRisk         string   `json:"jamming_risk" db:"jamming_risk"`
	Active              bool     `json:"active" db:"active"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

// ContractRFMonitoring represents customer-specific RF monitoring configuration
type ContractRFMonitoring struct {
	ContractRFID        int       `json:"contract_rf_id" db:"contract_rf_id"`
	ContractID          int       `json:"contract_id" db:"contract_id"`
	FrequencyID         int       `json:"frequency_id" db:"frequency_id"`
	Enabled             bool      `json:"enabled" db:"enabled"`
	CustomThresholdDBm  *float64  `json:"custom_threshold_dbm,omitempty" db:"custom_threshold_dbm"`
	AlertLevel          *string   `json:"alert_level,omitempty" db:"alert_level"`
	ScanIntervalSeconds int       `json:"scan_interval_seconds" db:"scan_interval_seconds"`
	AlertCooldownMinutes int      `json:"alert_cooldown_minutes" db:"alert_cooldown_minutes"`
	CustomerNotes       *string   `json:"customer_notes,omitempty" db:"customer_notes"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

// Mapping structures
type ContractCustomerMapping struct {
	ContractCustomerID int       `json:"contract_customer_id" db:"contract_customer_id"`
	ContractID         int       `json:"contract_id" db:"contract_id"`
	CustomerID         int       `json:"customer_id" db:"customer_id"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

type ContractNVRMapping struct {
	ContractNVRID int       `json:"contract_nvr_id" db:"contract_nvr_id"`
	ContractID    int       `json:"contract_id" db:"contract_id"`
	NVRID         int       `json:"nvr_id" db:"nvr_id"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

type NVRCameraMapping struct {
	NVRCameraID   int       `json:"nvr_camera_id" db:"nvr_camera_id"`
	NVRID         int       `json:"nvr_id" db:"nvr_id"`
	CameraID      int       `json:"camera_id" db:"camera_id"`
	ChannelNumber *int      `json:"channel_number,omitempty" db:"channel_number"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

type NVRControllerMapping struct {
	NVRControllerID int       `json:"nvr_controller_id" db:"nvr_controller_id"`
	NVRID           int       `json:"nvr_id" db:"nvr_id"`
	ControllerID    int       `json:"controller_id" db:"controller_id"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

type ControllerCameraSupport struct {
	ControllerCameraSupportID int       `json:"controller_camera_support_id" db:"controller_camera_support_id"`
	ControllerID              int       `json:"controller_id" db:"controller_id"`
	CameraID                  int       `json:"camera_id" db:"camera_id"`
	Priority                  int       `json:"priority" db:"priority"`
	CreatedAt                 time.Time `json:"created_at" db:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at" db:"updated_at"`
}

type ControllerVPNMapping struct {
	MappingID           int       `json:"mapping_id" db:"mapping_id"`
	ControllerID        int       `json:"controller_id" db:"controller_id"`
	VPNID               int       `json:"vpn_id" db:"vpn_id"`
	ClientAddress       string    `json:"client_address" db:"client_address"`
	ClientPublicKey     string    `json:"client_public_key" db:"client_public_key"`
	ClientPrivateKeyRef string    `json:"client_private_key_ref" db:"client_private_key_ref"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

// Helper types for JSON fields that can be NULL
type NullableJSON json.RawMessage

func (n *NullableJSON) Scan(value interface{}) error {
	if value == nil {
		*n = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*n = v
	case string:
		*n = []byte(v)
	default:
		return fmt.Errorf("cannot scan type %T into NullableJSON", value)
	}
	return nil
}

func (n NullableJSON) Value() (driver.Value, error) {
	if n == nil {
		return nil, nil
	}
	return []byte(n), nil
}
MODELSFILE

# Create handlers/handlers.go
cat > handlers/handlers.go << 'HANDLERSFILE'
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sense-security/api/db"
)

// Handler holds all the handler dependencies
type Handler struct {
	db *db.DB
}

// New creates a new handler with the given database
func New(database *db.DB) *Handler {
	return &Handler{
		db: database,
	}
}

// HealthCheck returns the health status of the API
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "ok",
		"service": "sense-security-api",
	}
	respondJSON(w, http.StatusOK, response)
}

// ReadinessCheck checks if the API is ready to serve requests
func (h *Handler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	if err := h.db.Ping(); err != nil {
		respondError(w, http.StatusServiceUnavailable, "Database connection failed")
		return
	}
	
	response := map[string]string{
		"status": "ready",
		"database": "connected",
	}
	respondJSON(w, http.StatusOK, response)
}

// Helper functions

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			// Log error but don't write again to avoid multiple writes
			_ = err
		}
	}
}

// respondError writes an error response
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// parseJSON parses the request body into the given interface
func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// getPaginationParams extracts pagination parameters from request
func getPaginationParams(r *http.Request) (limit, offset int) {
	limit = 50 // default
	offset = 0 // default
	
	// Parse from query parameters
	query := r.URL.Query()
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := query.Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	
	return limit, offset
}
HANDLERSFILE

# Create handlers/customers.go
cat > handlers/customers.go << 'CUSTOMERSFILE'
package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/models"
)

// ListCustomers returns a list of all customers
func (h *Handler) ListCustomers(w http.ResponseWriter, r *http.Request) {
	limit, offset := getPaginationParams(r)
	
	query := `
		SELECT customer_id, name_on_contract, address, unique_id, 
		       email, phone_number, created_at, updated_at
		FROM Customer
		ORDER BY customer_id DESC
		LIMIT ? OFFSET ?
	`
	
	rows, err := h.db.Query(query, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch customers")
		return
	}
	defer rows.Close()
	
	customers := []models.Customer{}
	for rows.Next() {
		var c models.Customer
		err := rows.Scan(
			&c.CustomerID, &c.NameOnContract, &c.Address, &c.UniqueID,
			&c.Email, &c.PhoneNumber, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to scan customer")
			return
		}
		customers = append(customers, c)
	}
	
	respondJSON(w, http.StatusOK, customers)
}

// GetCustomer returns a single customer by ID
func (h *Handler) GetCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	var c models.Customer
	query := `
		SELECT customer_id, name_on_contract, address, unique_id, 
		       email, phone_number, created_at, updated_at
		FROM Customer
		WHERE customer_id = ?
	`
	
	err = h.db.QueryRow(query, id).Scan(
		&c.CustomerID, &c.NameOnContract, &c.Address, &c.UniqueID,
		&c.Email, &c.PhoneNumber, &c.CreatedAt, &c.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Customer not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch customer")
		return
	}
	
	respondJSON(w, http.StatusOK, c)
}

// CreateCustomer creates a new customer
func (h *Handler) CreateCustomer(w http.ResponseWriter, r *http.Request) {
	var c models.Customer
	if err := parseJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate required fields
	if c.NameOnContract == "" || c.Address == "" || c.UniqueID == "" {
		respondError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	
	query := `
		INSERT INTO Customer (name_on_contract, address, unique_id, email, phone_number)
		VALUES (?, ?, ?, ?, ?)
	`
	
	result, err := h.db.Exec(query, c.NameOnContract, c.Address, c.UniqueID, c.Email, c.PhoneNumber)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create customer")
		return
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get customer ID")
		return
	}
	
	c.CustomerID = int(id)
	respondJSON(w, http.StatusCreated, c)
}

// UpdateCustomer updates an existing customer
func (h *Handler) UpdateCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	var c models.Customer
	if err := parseJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate required fields
	if c.NameOnContract == "" || c.Address == "" || c.UniqueID == "" {
		respondError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	
	query := `
		UPDATE Customer 
		SET name_on_contract = ?, address = ?, unique_id = ?, 
		    email = ?, phone_number = ?
		WHERE customer_id = ?
	`
	
	result, err := h.db.Exec(query, c.NameOnContract, c.Address, c.UniqueID, 
		c.Email, c.PhoneNumber, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update customer")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check update result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Customer not found")
		return
	}
	
	c.CustomerID = id
	respondJSON(w, http.StatusOK, c)
}

// DeleteCustomer deletes a customer
func (h *Handler) DeleteCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	// Check if customer has any contracts
	var count int
	checkQuery := `
		SELECT COUNT(*) 
		FROM Contract_Customer_Mapping 
		WHERE customer_id = ?
	`
	err = h.db.QueryRow(checkQuery, id).Scan(&count)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check customer contracts")
		return
	}
	
	if count > 0 {
		respondError(w, http.StatusConflict, "Cannot delete customer with active contracts")
		return
	}
	
	query := `DELETE FROM Customer WHERE customer_id = ?`
	result, err := h.db.Exec(query, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete customer")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check delete result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Customer not found")
		return
	}
	
	respondJSON(w, http.StatusNoContent, nil)
}
CUSTOMERSFILE

# Create handlers/contracts.go
cat > handlers/contracts.go << 'CONTRACTSFILE'
package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/models"
)

// ListContracts returns a list of all contracts
func (h *Handler) ListContracts(w http.ResponseWriter, r *http.Request) {
	limit, offset := getPaginationParams(r)
	
	query := `
		SELECT contract_id, service_address, notification_email, 
		       notification_phone, start_date, end_date, created_at, updated_at
		FROM Contract
		ORDER BY contract_id DESC
		LIMIT ? OFFSET ?
	`
	
	rows, err := h.db.Query(query, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch contracts")
		return
	}
	defer rows.Close()
	
	contracts := []models.Contract{}
	for rows.Next() {
		var c models.Contract
		err := rows.Scan(
			&c.ContractID, &c.ServiceAddress, &c.NotificationEmail,
			&c.NotificationPhone, &c.StartDate, &c.EndDate,
			&c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to scan contract")
			return
		}
		contracts = append(contracts, c)
	}
	
	respondJSON(w, http.StatusOK, contracts)
}

// GetContract returns a single contract by ID
func (h *Handler) GetContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	var c models.Contract
	query := `
		SELECT contract_id, service_address, notification_email, 
		       notification_phone, start_date, end_date, created_at, updated_at
		FROM Contract
		WHERE contract_id = ?
	`
	
	err = h.db.QueryRow(query, id).Scan(
		&c.ContractID, &c.ServiceAddress, &c.NotificationEmail,
		&c.NotificationPhone, &c.StartDate, &c.EndDate,
		&c.CreatedAt, &c.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Contract not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch contract")
		return
	}
	
	respondJSON(w, http.StatusOK, c)
}

// CreateContract creates a new contract
func (h *Handler) CreateContract(w http.ResponseWriter, r *http.Request) {
	var c models.Contract
	if err := parseJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate required fields
	if c.ServiceAddress == "" {
		respondError(w, http.StatusBadRequest, "Service address is required")
		return
	}
	
	// Validate dates
	if c.EndDate.Before(c.StartDate) || c.EndDate.Equal(c.StartDate) {
		respondError(w, http.StatusBadRequest, "End date must be after start date")
		return
	}
	
	query := `
		INSERT INTO Contract (service_address, notification_email, 
		                     notification_phone, start_date, end_date)
		VALUES (?, ?, ?, ?, ?)
	`
	
	result, err := h.db.Exec(query, c.ServiceAddress, c.NotificationEmail,
		c.NotificationPhone, c.StartDate, c.EndDate)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create contract")
		return
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get contract ID")
		return
	}
	
	c.ContractID = int(id)
	respondJSON(w, http.StatusCreated, c)
}

// UpdateContract updates an existing contract
func (h *Handler) UpdateContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	var c models.Contract
	if err := parseJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate required fields
	if c.ServiceAddress == "" {
		respondError(w, http.StatusBadRequest, "Service address is required")
		return
	}
	
	// Validate dates
	if c.EndDate.Before(c.StartDate) || c.EndDate.Equal(c.StartDate) {
		respondError(w, http.StatusBadRequest, "End date must be after start date")
		return
	}
	
	query := `
		UPDATE Contract 
		SET service_address = ?, notification_email = ?, 
		    notification_phone = ?, start_date = ?, end_date = ?
		WHERE contract_id = ?
	`
	
	result, err := h.db.Exec(query, c.ServiceAddress, c.NotificationEmail,
		c.NotificationPhone, c.StartDate, c.EndDate, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update contract")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check update result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Contract not found")
		return
	}
	
	c.ContractID = id
	respondJSON(w, http.StatusOK, c)
}

// DeleteContract deletes a contract
func (h *Handler) DeleteContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	// Begin transaction to handle cascading deletes
	tx, err := h.db.Begin()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to start transaction")
		return
	}
	defer tx.Rollback()
	
	// Delete related mappings first
	deleteQueries := []string{
		"DELETE FROM Contract_Customer_Mapping WHERE contract_id = ?",
		"DELETE FROM Contract_Service_Tier WHERE contract_id = ?",
		"DELETE FROM Contract_NVR_Mapping WHERE contract_id = ?",
		"DELETE FROM Contract_RF_Monitoring WHERE contract_id = ?",
	}
	
	for _, q := range deleteQueries {
		if _, err := tx.Exec(q, id); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to delete contract relations")
			return
		}
	}
	
	// Delete the contract
	result, err := tx.Exec("DELETE FROM Contract WHERE contract_id = ?", id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete contract")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check delete result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Contract not found")
		return
	}
	
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to commit transaction")
		return
	}
	
	respondJSON(w, http.StatusNoContent, nil)
}

// ListContractCustomers lists all customers associated with a contract
func (h *Handler) ListContractCustomers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	query := `
		SELECT c.customer_id, c.name_on_contract, c.address, c.unique_id, 
		       c.email, c.phone_number, c.created_at, c.updated_at
		FROM Customer c
		JOIN Contract_Customer_Mapping ccm ON c.customer_id = ccm.customer_id
		WHERE ccm.contract_id = ?
		ORDER BY c.customer_id
	`
	
	rows, err := h.db.Query(query, contractID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch contract customers")
		return
	}
	defer rows.Close()
	
	customers := []models.Customer{}
	for rows.Next() {
		var c models.Customer
		err := rows.Scan(
			&c.CustomerID, &c.NameOnContract, &c.Address, &c.UniqueID,
			&c.Email, &c.PhoneNumber, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to scan customer")
			return
		}
		customers = append(customers, c)
	}
	
	respondJSON(w, http.StatusOK, customers)
}

// AddCustomerToContract adds a customer to a contract
func (h *Handler) AddCustomerToContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	customerID, err := strconv.Atoi(vars["customerId"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	// Check if mapping already exists
	var exists bool
	checkQuery := `
		SELECT EXISTS(
			SELECT 1 FROM Contract_Customer_Mapping 
			WHERE contract_id = ? AND customer_id = ?
		)
	`
	err = h.db.QueryRow(checkQuery, contractID, customerID).Scan(&exists)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check existing mapping")
		return
	}
	
	if exists {
		respondError(w, http.StatusConflict, "Customer already assigned to contract")
		return
	}
	
	// Create the mapping
	insertQuery := `
		INSERT INTO Contract_Customer_Mapping (contract_id, customer_id)
		VALUES (?, ?)
	`
	
	_, err = h.db.Exec(insertQuery, contractID, customerID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add customer to contract")
		return
	}
	
	respondJSON(w, http.StatusCreated, map[string]string{
		"message": "Customer added to contract successfully",
	})
}

// RemoveCustomerFromContract removes a customer from a contract
func (h *Handler) RemoveCustomerFromContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	customerID, err := strconv.Atoi(vars["customerId"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	query := `
		DELETE FROM Contract_Customer_Mapping 
		WHERE contract_id = ? AND customer_id = ?
	`
	
	result, err := h.db.Exec(query, contractID, customerID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to remove customer from contract")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check delete result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Customer not assigned to this contract")
		return
	}
	
	respondJSON(w, http.StatusNoContent, nil)
}

// AssignServiceTier assigns a service tier to a contract
func (h *Handler) AssignServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	var req struct {
		ServiceTierID int       `json:"service_tier_id"`
		StartDate     time.Time `json:"start_date"`
		EndDate       time.Time `json:"end_date"`
	}
	
	if err := parseJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate dates
	if req.EndDate.Before(req.StartDate) || req.EndDate.Equal(req.StartDate) {
		respondError(w, http.StatusBadRequest, "End date must be after start date")
		return
	}
	
	// Check for overlapping service tiers
	overlapQuery := `
		SELECT EXISTS(
			SELECT 1 FROM Contract_Service_Tier
			WHERE contract_id = ?
			AND ((start_date <= ? AND end_date >= ?)
			OR (start_date <= ? AND end_date >= ?))
		)
	`
	
	var hasOverlap bool
	err = h.db.QueryRow(overlapQuery, contractID, req.StartDate, req.StartDate, 
		req.EndDate, req.EndDate).Scan(&hasOverlap)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check overlapping tiers")
		return
	}
	
	if hasOverlap {
		respondError(w, http.StatusConflict, "Service tier dates overlap with existing assignment")
		return
	}
	
	// Insert the new service tier assignment
	insertQuery := `
		INSERT INTO Contract_Service_Tier (contract_id, service_tier_id, start_date, end_date)
		VALUES (?, ?, ?, ?)
	`
	
	result, err := h.db.Exec(insertQuery, contractID, req.ServiceTierID, req.StartDate, req.EndDate)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to assign service tier")
		return
	}
	
	id, _ := result.LastInsertId()
	
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"contract_service_tier_id": id,
		"message": "Service tier assigned successfully",
	})
}

// GetCurrentServiceTier gets the current active service tier for a contract
func (h *Handler) GetCurrentServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	query := `
		SELECT st.service_tier_id, st.name, st.description, st.config,
		       cst.start_date, cst.end_date
		FROM Service_Tier st
		JOIN Contract_Service_Tier cst ON st.service_tier_id = cst.service_tier_id
		WHERE cst.contract_id = ?
		AND CURDATE() BETWEEN cst.start_date AND cst.end_date
		ORDER BY cst.start_date DESC
		LIMIT 1
	`
	
	var result struct {
		models.ServiceTier
		StartDate time.Time `json:"start_date"`
		EndDate   time.Time `json:"end_date"`
	}
	
	err = h.db.QueryRow(query, contractID).Scan(
		&result.ServiceTierID, &result.Name, &result.Description,
		&result.Config, &result.StartDate, &result.EndDate,
	)
	
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "No active service tier found for contract")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch service tier")
		return
	}
	
	respondJSON(w, http.StatusOK, result)
}
CONTRACTSFILE

echo "All files created!"
