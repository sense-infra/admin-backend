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

// Additional request/response models for handlers

// CreateContractRequest represents a request to create a new contract
type CreateContractRequest struct {
	ServiceAddress    string    `json:"service_address" validate:"required"`
	NotificationEmail *string   `json:"notification_email" validate:"omitempty,email"`
	NotificationPhone *string   `json:"notification_phone" validate:"omitempty"`
	StartDate         time.Time `json:"start_date" validate:"required"`
	EndDate           time.Time `json:"end_date" validate:"required"`
}

// UpdateContractRequest represents a request to update a contract
type UpdateContractRequest struct {
	ServiceAddress    *string    `json:"service_address"`
	NotificationEmail *string    `json:"notification_email" validate:"omitempty,email"`
	NotificationPhone *string    `json:"notification_phone"`
	StartDate         *time.Time `json:"start_date"`
	EndDate           *time.Time `json:"end_date"`
}

// CreateCustomerRequest represents a request to create a new customer
type CreateCustomerRequest struct {
	NameOnContract string  `json:"name_on_contract" validate:"required"`
	Address        string  `json:"address" validate:"required"`
	UniqueID       string  `json:"unique_id" validate:"required"`
	Email          *string `json:"email" validate:"omitempty,email"`
	PhoneNumber    *string `json:"phone_number"`
}

// UpdateCustomerRequest represents a request to update a customer
type UpdateCustomerRequest struct {
	NameOnContract *string `json:"name_on_contract"`
	Address        *string `json:"address"`
	Email          *string `json:"email" validate:"omitempty,email"`
	PhoneNumber    *string `json:"phone_number"`
}
