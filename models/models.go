package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CustomDate handles date-only strings in JSON (YYYY-MM-DD format)
type CustomDate struct {
	time.Time
}

// UnmarshalJSON implements the json.Unmarshaler interface for CustomDate
func (cd *CustomDate) UnmarshalJSON(data []byte) error {
	// Remove quotes from JSON string
	dateStr := strings.Trim(string(data), `"`)
	
	if dateStr == "null" || dateStr == "" {
		cd.Time = time.Time{}
		return nil
	}
	
	// Parse date in YYYY-MM-DD format
	parsedTime, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return fmt.Errorf("invalid date format: %s, expected YYYY-MM-DD", dateStr)
	}
	
	cd.Time = parsedTime
	return nil
}

// MarshalJSON implements the json.Marshaler interface for CustomDate
func (cd CustomDate) MarshalJSON() ([]byte, error) {
	if cd.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(cd.Time.Format("2006-01-02"))
}

// Scan implements the sql.Scanner interface for CustomDate
func (cd *CustomDate) Scan(value interface{}) error {
	if value == nil {
		cd.Time = time.Time{}
		return nil
	}
	
	switch v := value.(type) {
	case time.Time:
		cd.Time = v
		return nil
	case string:
		parsedTime, err := time.Parse("2006-01-02", v)
		if err != nil {
			return err
		}
		cd.Time = parsedTime
		return nil
	default:
		return fmt.Errorf("cannot scan %T into CustomDate", value)
	}
}

// Value implements the driver.Valuer interface for CustomDate
func (cd CustomDate) Value() (driver.Value, error) {
	if cd.Time.IsZero() {
		return nil, nil
	}
	return cd.Time.Format("2006-01-02"), nil
}

// String returns the date in YYYY-MM-DD format
func (cd CustomDate) String() string {
	if cd.Time.IsZero() {
		return ""
	}
	return cd.Time.Format("2006-01-02")
}

// IsZero reports whether cd represents the zero time instant
func (cd CustomDate) IsZero() bool {
	return cd.Time.IsZero()
}

// Before reports whether the time instant cd is before u
func (cd CustomDate) Before(u CustomDate) bool {
	return cd.Time.Before(u.Time)
}

// After reports whether the time instant cd is after u
func (cd CustomDate) After(u CustomDate) bool {
	return cd.Time.After(u.Time)
}

// Equal reports whether cd and u represent the same time instant
func (cd CustomDate) Equal(u CustomDate) bool {
	return cd.Time.Equal(u.Time)
}

// Customer represents a customer in the system
type Customer struct {
	CustomerID     int       `json:"customer_id" db:"customer_id"`
	NameOnContract string    `json:"name_on_contract" db:"name_on_contract"`
	Address        string    `json:"address" db:"address"`
	UniqueID       string    `json:"unique_id" db:"unique_id"`
	Email          *string   `json:"email,omitempty" db:"email"`
	PhoneNumber    *string   `json:"phone_number,omitempty" db:"phone_number"`
	PasswordHash         string     `json:"-" db:"password_hash"` // Never include in JSON
	ForcePasswordChange  bool       `json:"force_password_change" db:"force_password_change"`
	LastLogin            *time.Time `json:"last_login" db:"last_login"`
	FailedLoginAttempts  int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil          *time.Time `json:"locked_until" db:"locked_until"`
	PasswordChangedAt    time.Time  `json:"password_changed_at" db:"password_changed_at"`
	Active               bool       `json:"active" db:"active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// Customer helper methods
func (c *Customer) IsLocked() bool {
	return c.LockedUntil != nil && c.LockedUntil.After(time.Now())
}

func (c *Customer) ShouldForcePasswordChange() bool {
	return c.ForcePasswordChange || c.PasswordChangedAt.Before(time.Now().AddDate(0, -6, 0)) // 6 months
}

// CustomerSession represents an active customer session
type CustomerSession struct {
	SessionID    string     `json:"session_id" db:"session_id"`
	CustomerID   int        `json:"customer_id" db:"customer_id"`
	TokenHash    string     `json:"-" db:"token_hash"`
	IPAddress    *string    `json:"ip_address" db:"ip_address"`
	UserAgent    *string    `json:"user_agent" db:"user_agent"`
	ExpiresAt    time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	LastActivity time.Time  `json:"last_activity" db:"last_activity"`

	// Joined fields
	Customer *Customer `json:"customer,omitempty"`
}

func (s *CustomerSession) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}

// Customer dashboard and view models
type CustomerDashboard struct {
	Customer              Customer                   `json:"customer"`
	TotalContracts        int                        `json:"total_contracts"`
	ActiveContracts       int                        `json:"active_contracts"`
	TotalNVRs            int                        `json:"total_nvrs"`
	TotalControllers     int                        `json:"total_controllers"`
	TotalCameras         int                        `json:"total_cameras"`
	OnlineCameras        int                        `json:"online_cameras"`
	MonitoredFrequencies int                        `json:"monitored_frequencies"`
	ActiveRFMonitors     int                        `json:"active_rf_monitors"`
	Contracts            []CustomerContractDetail   `json:"contracts"`
}

type CustomerContractDetail struct {
	CustomerID             int                      `json:"customer_id" db:"customer_id"`
	ContractID             int                      `json:"contract_id" db:"contract_id"`
	ServiceAddress         string                   `json:"service_address" db:"service_address"`
	NotificationEmail      *string                  `json:"notification_email,omitempty" db:"notification_email"`
	NotificationPhone      *string                  `json:"notification_phone,omitempty" db:"notification_phone"`
	StartDate              time.Time                `json:"start_date" db:"start_date"`
	EndDate                time.Time                `json:"end_date" db:"end_date"`
	ContractStatus         string                   `json:"contract_status" db:"contract_status"` // MAKE SURE THIS IS HERE
	ServiceTierID          *int                     `json:"service_tier_id,omitempty" db:"service_tier_id"`
	ServiceTierName        *string                  `json:"service_tier_name,omitempty" db:"service_tier_name"`
	ServiceTierDescription *string                  `json:"service_tier_description,omitempty" db:"service_tier_description"`
	TierStartDate          *time.Time               `json:"tier_start_date,omitempty" db:"tier_start_date"`
	TierEndDate            *time.Time               `json:"tier_end_date,omitempty" db:"tier_end_date"`
	Equipment              []CustomerEquipmentItem  `json:"equipment"`
	RFMonitoring           []CustomerRFMonitorItem  `json:"rf_monitoring"`
}

// Replace the existing CustomerEquipmentItem struct with this:
type CustomerEquipmentItem struct {
	// Customer and Contract Info
	CustomerID         int      `json:"customer_id" db:"customer_id"` // ADD THIS LINE
	ContractID         int      `json:"contract_id" db:"contract_id"` // ADD THIS LINE
	
	// NVR
	NVRID              *int     `json:"nvr_id,omitempty" db:"nvr_id"`
	NVRModel           *string  `json:"nvr_model,omitempty" db:"nvr_model"`
	NVRSerial          *string  `json:"nvr_serial,omitempty" db:"nvr_serial"`
	NVRFirmware        *string  `json:"nvr_firmware,omitempty" db:"nvr_firmware"`
	StorageCapacityGB  *int     `json:"storage_capacity_gb,omitempty" db:"storage_capacity_gb"`

	// Controller
	ControllerID       *int     `json:"controller_id,omitempty" db:"controller_id"`
	ControllerType     *string  `json:"controller_type,omitempty" db:"controller_type"`
	ControllerModel    *string  `json:"controller_model,omitempty" db:"controller_model"`
	ControllerSerial   *string  `json:"controller_serial,omitempty" db:"controller_serial"`
	ControllerFirmware *string  `json:"controller_firmware,omitempty" db:"controller_firmware"`
	OSArchitecture     *string  `json:"os_architecture,omitempty" db:"os_architecture"`
	HWEncryptionEnabled *bool   `json:"hw_encryption_enabled,omitempty" db:"hw_encryption_enabled"`
	SWEncryptionEnabled *bool   `json:"sw_encryption_enabled,omitempty" db:"sw_encryption_enabled"`

	// Camera
	CameraID           *int     `json:"camera_id,omitempty" db:"camera_id"`
	CameraName         *string  `json:"camera_name,omitempty" db:"camera_name"`
	CameraModel        *string  `json:"camera_model,omitempty" db:"camera_model"`
	CameraSerial       *string  `json:"camera_serial,omitempty" db:"camera_serial"`
	Resolution         *string  `json:"resolution,omitempty" db:"resolution"`
	CameraStatus       *string  `json:"camera_status,omitempty" db:"camera_status"`
	TalkBackSupport    *bool    `json:"talk_back_support,omitempty" db:"talk_back_support"`
	NightVisionSupport *bool    `json:"night_vision_support,omitempty" db:"night_vision_support"`
	CameraPriority     *int     `json:"camera_priority,omitempty" db:"camera_priority"`
	ChannelNumber      *int     `json:"channel_number,omitempty" db:"channel_number"`
}

// Replace the existing CustomerRFMonitorItem struct with this:
type CustomerRFMonitorItem struct {
	CustomerID          int      `json:"customer_id" db:"customer_id"` // ADD THIS LINE
	ContractID          int      `json:"contract_id" db:"contract_id"` // ADD THIS LINE
	ContractRFID        int      `json:"contract_rf_id" db:"contract_rf_id"`
	FrequencyID         int      `json:"frequency_id" db:"frequency_id"`
	FrequencyMHz        float64  `json:"frequency_mhz" db:"frequency_mhz"`
	FrequencyName       string   `json:"frequency_name" db:"frequency_name"`
	Description         *string  `json:"frequency_description,omitempty" db:"frequency_description"`
	Category            string   `json:"category" db:"category"`
	TypicalUsage        *string  `json:"typical_usage,omitempty" db:"typical_usage"`
	SecurityImportance  string   `json:"security_importance" db:"security_importance"`
	JammingRisk         string   `json:"jamming_risk" db:"jamming_risk"`
	MonitoringEnabled   bool     `json:"monitoring_enabled" db:"monitoring_enabled"`
	ThresholdDBm        float64  `json:"threshold_dbm" db:"threshold_dbm"`
	AlertLevel          string   `json:"alert_level" db:"alert_level"`
	ScanIntervalSeconds int      `json:"scan_interval_seconds" db:"scan_interval_seconds"`
	AlertCooldownMinutes int     `json:"alert_cooldown_minutes" db:"alert_cooldown_minutes"`
	CustomerNotes       *string  `json:"customer_notes,omitempty" db:"customer_notes"`
}

// Customer authentication request/response models
type CustomerLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type CustomerLoginResponse struct {
	Token               string   `json:"token"`
	ExpiresAt           time.Time `json:"expires_at"`
	Customer            Customer `json:"customer"`
	ForcePasswordChange bool     `json:"force_password_change"`
}

type CustomerChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// Customer Auth Context (similar to admin AuthContext)
type CustomerAuthContext struct {
	CustomerID  *int     `json:"customer_id,omitempty"`
	Email       *string  `json:"email,omitempty"`
	Name        *string  `json:"name,omitempty"`
	SessionID   *string  `json:"session_id,omitempty"`
	ContractIDs []int    `json:"contract_ids,omitempty"` // For quick contract access validation
}

// CanAccessContract checks if the customer can access a specific contract
func (cac *CustomerAuthContext) CanAccessContract(contractID int) bool {
	if cac.ContractIDs == nil {
		return false
	}
	for _, id := range cac.ContractIDs {
		if id == contractID {
			return true
		}
	}
	return false
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

// Enhanced contract models with relationships
type ContractWithDetails struct {
	ContractID         int                  `json:"contract_id" db:"contract_id"`
	ServiceAddress     string               `json:"service_address" db:"service_address"`
	NotificationEmail  *string              `json:"notification_email,omitempty" db:"notification_email"`
	NotificationPhone  *string              `json:"notification_phone,omitempty" db:"notification_phone"`
	StartDate          time.Time            `json:"start_date" db:"start_date"`
	EndDate            time.Time            `json:"end_date" db:"end_date"`
	CreatedAt          time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at" db:"updated_at"`
	Customers          []CustomerBasic      `json:"customers"`
	CurrentServiceTier *ServiceTierBasic    `json:"current_service_tier,omitempty"`
}

// Customer with contracts for detailed view
type CustomerWithContracts struct {
	CustomerID     int             `json:"customer_id" db:"customer_id"`
	NameOnContract string          `json:"name_on_contract" db:"name_on_contract"`
	Address        string          `json:"address" db:"address"`
	UniqueID       string          `json:"unique_id" db:"unique_id"`
	Email          *string         `json:"email,omitempty" db:"email"`
	PhoneNumber    *string         `json:"phone_number,omitempty" db:"phone_number"`
	CreatedAt      time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at" db:"updated_at"`
	Contracts      []ContractBasic `json:"contracts"`
}

// Basic customer info for relationships
type CustomerBasic struct {
	CustomerID     int     `json:"customer_id" db:"customer_id"`
	NameOnContract string  `json:"name_on_contract" db:"name_on_contract"`
	Email          *string `json:"email,omitempty" db:"email"`
	PhoneNumber    *string `json:"phone_number,omitempty" db:"phone_number"`
}

// Basic contract info for relationships
type ContractBasic struct {
	ContractID       int       `json:"contract_id" db:"contract_id"`
	ServiceAddress   string    `json:"service_address" db:"service_address"`
	StartDate        time.Time `json:"start_date" db:"start_date"`
	EndDate          time.Time `json:"end_date" db:"end_date"`
	ServiceTierName  *string   `json:"service_tier_name,omitempty" db:"service_tier_name"`
}

// Basic service tier info for relationships
type ServiceTierBasic struct {
	ServiceTierID int     `json:"service_tier_id" db:"service_tier_id"`
	Name          string  `json:"name" db:"name"`
	Description   *string `json:"description,omitempty" db:"description"`
}

// Request models for contract creation with relationships - UPDATED TO USE CustomDate
type CreateContractWithRelationsRequest struct {
	ServiceAddress    string     `json:"service_address" validate:"required"`
	NotificationEmail *string    `json:"notification_email" validate:"omitempty,email"`
	NotificationPhone *string    `json:"notification_phone" validate:"omitempty"`
	StartDate         CustomDate `json:"start_date" validate:"required"`
	EndDate           CustomDate `json:"end_date" validate:"required"`
	CustomerID        int        `json:"customer_id" validate:"required"`
	ServiceTierID     int        `json:"service_tier_id" validate:"required"`
}

// Request models for contract updates with relationships - UPDATED TO USE CustomDate
type UpdateContractWithRelationsRequest struct {
	ServiceAddress    *string     `json:"service_address"`
	NotificationEmail *string     `json:"notification_email" validate:"omitempty,email"`
	NotificationPhone *string     `json:"notification_phone"`
	StartDate         *CustomDate `json:"start_date"`
	EndDate           *CustomDate `json:"end_date"`
	CustomerID        *int        `json:"customer_id"`
	ServiceTierID     *int        `json:"service_tier_id"`
}

// Service tier request models
type CreateServiceTierRequest struct {
	Name        string          `json:"name" validate:"required"`
	Description *string         `json:"description"`
	Config      json.RawMessage `json:"config"`
}

type UpdateServiceTierRequest struct {
	Name        *string          `json:"name"`
	Description *string          `json:"description"`
	Config      *json.RawMessage `json:"config"`
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

// CreateContractRequest represents a request to create a new contract - UPDATED TO USE CustomDate
type CreateContractRequest struct {
	ServiceAddress    string     `json:"service_address" validate:"required"`
	NotificationEmail *string    `json:"notification_email" validate:"omitempty,email"`
	NotificationPhone *string    `json:"notification_phone" validate:"omitempty"`
	StartDate         CustomDate `json:"start_date" validate:"required"`
	EndDate           CustomDate `json:"end_date" validate:"required"`
}

// UpdateContractRequest represents a request to update a contract - UPDATED TO USE CustomDate
type UpdateContractRequest struct {
	ServiceAddress    *string     `json:"service_address"`
	NotificationEmail *string     `json:"notification_email" validate:"omitempty,email"`
	NotificationPhone *string     `json:"notification_phone"`
	StartDate         *CustomDate `json:"start_date"`
	EndDate           *CustomDate `json:"end_date"`
}

type CreateCustomerRequest struct {
	NameOnContract string  `json:"name_on_contract" validate:"required"`
	Address        string  `json:"address" validate:"required"`
	UniqueID       string  `json:"unique_id" validate:"required"`
	Email          *string `json:"email" validate:"omitempty,email"`
	PhoneNumber    *string `json:"phone_number"`
	Password       string  `json:"password" validate:"required,min=8"` // NEW: Required password field
	Active         *bool   `json:"active"` // NEW: Optional, defaults to true
}

// Admin customer password reset request
type AdminResetCustomerPasswordRequest struct {
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// Admin customer management requests (updated)
type UpdateCustomerRequest struct {
	NameOnContract *string `json:"name_on_contract"`
	Address        *string `json:"address"`
	Email          *string `json:"email" validate:"omitempty,email"`
	PhoneNumber    *string `json:"phone_number"`
	Active         *bool   `json:"active"` // NEW: Admin can activate/deactivate customers
}
