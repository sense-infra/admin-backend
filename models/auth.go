package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Permissions represents a JSON object for role/API key permissions
type Permissions map[string][]string

// Value implements the driver.Valuer interface for database storage
func (p Permissions) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
}

// Scan implements the sql.Scanner interface for database retrieval
func (p *Permissions) Scan(value interface{}) error {
	if value == nil {
		*p = nil
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into Permissions", value)
	}
	
	return json.Unmarshal(bytes, p)
}

// HasPermission checks if the permissions include a specific action for a resource
func (p Permissions) HasPermission(resource, action string) bool {
	if p == nil {
		return false
	}
	
	actions, exists := p[resource]
	if !exists {
		return false
	}
	
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

// ContractAccess represents JSON array of contract IDs for API key access control
type ContractAccess []int

// Value implements the driver.Valuer interface
func (c ContractAccess) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}

// Scan implements the sql.Scanner interface
func (c *ContractAccess) Scan(value interface{}) error {
	if value == nil {
		*c = nil
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into ContractAccess", value)
	}
	
	return json.Unmarshal(bytes, c)
}

// HasAccess checks if the contract access allows access to a specific contract
func (c ContractAccess) HasAccess(contractID int) bool {
	if c == nil {
		return true // nil means access to all contracts
	}
	
	for _, id := range c {
		if id == contractID {
			return true
		}
	}
	return false
}

// UserRole represents a system role with permissions
type UserRole struct {
	RoleID      int         `json:"role_id" db:"role_id"`
	Name        string      `json:"name" db:"name"`
	Description *string     `json:"description" db:"description"`
	Permissions Permissions `json:"permissions" db:"permissions"`
	Active      bool        `json:"active" db:"active"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

// SystemUser represents a system user account
type SystemUser struct {
	UserID               int        `json:"user_id" db:"user_id"`
	Username             string     `json:"username" db:"username"`
	Email                string     `json:"email" db:"email"`
	PasswordHash         string     `json:"-" db:"password_hash"` // Never include in JSON
	RoleID               int        `json:"role_id" db:"role_id"`
	FirstName            *string    `json:"first_name" db:"first_name"`
	LastName             *string    `json:"last_name" db:"last_name"`
	ForcePasswordChange  bool       `json:"force_password_change" db:"force_password_change"`
	LastLogin            *time.Time `json:"last_login" db:"last_login"`
	FailedLoginAttempts  int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil          *time.Time `json:"locked_until" db:"locked_until"`
	PasswordChangedAt    time.Time  `json:"password_changed_at" db:"password_changed_at"`
	Active               bool       `json:"active" db:"active"`
	CreatedBy            *int       `json:"created_by" db:"created_by"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	
	// Joined fields
	Role     *UserRole    `json:"role,omitempty"`
	Creator  *SystemUser  `json:"created_by_user,omitempty"`
}

// IsLocked checks if the user account is currently locked
func (u *SystemUser) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// ShouldForcePasswordChange checks if user should be forced to change password
func (u *SystemUser) ShouldForcePasswordChange() bool {
	return u.ForcePasswordChange || u.PasswordChangedAt.Before(time.Now().AddDate(0, -6, 0)) // 6 months
}

// UserSession represents an active user session
type UserSession struct {
	SessionID    string     `json:"session_id" db:"session_id"`
	UserID       int        `json:"user_id" db:"user_id"`
	TokenHash    string     `json:"-" db:"token_hash"`
	IPAddress    *string    `json:"ip_address" db:"ip_address"`
	UserAgent    *string    `json:"user_agent" db:"user_agent"`
	ExpiresAt    time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	LastActivity time.Time  `json:"last_activity" db:"last_activity"`
	
	// Joined fields
	User *SystemUser `json:"user,omitempty"`
}

// IsExpired checks if the session has expired
func (s *UserSession) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}

// APIKey represents an API key for external access
type APIKey struct {
	APIKeyID         int             `json:"api_key_id" db:"api_key_id"`
	KeyName          string          `json:"key_name" db:"key_name"`
	KeyHash          string          `json:"-" db:"key_hash"`
	KeyPrefix        string          `json:"key_prefix" db:"key_prefix"`
	Permissions      Permissions     `json:"permissions" db:"permissions"`
	ContractAccess   ContractAccess  `json:"contract_access" db:"contract_access"`
	RateLimitPerHour int             `json:"rate_limit_per_hour" db:"rate_limit_per_hour"`
	CreatedBy        int             `json:"created_by" db:"created_by"`
	Description      *string         `json:"description" db:"description"`
	Active           bool            `json:"active" db:"active"`
	LastUsed         *time.Time      `json:"last_used" db:"last_used"`
	UsageCount       int64           `json:"usage_count" db:"usage_count"`
	ExpiresAt        *time.Time      `json:"expires_at" db:"expires_at"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`
	
	// Joined fields
	Creator *SystemUser `json:"created_by_user,omitempty"`
}

// IsExpired checks if the API key has expired
func (k *APIKey) IsExpired() bool {
	return k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now())
}

// APIKeyUsageLog represents an API key usage log entry
type APIKeyUsageLog struct {
	LogID             int64      `json:"log_id" db:"log_id"`
	APIKeyID          int        `json:"api_key_id" db:"api_key_id"`
	Endpoint          string     `json:"endpoint" db:"endpoint"`
	Method            string     `json:"method" db:"method"`
	IPAddress         *string    `json:"ip_address" db:"ip_address"`
	UserAgent         *string    `json:"user_agent" db:"user_agent"`
	ResponseStatus    *int       `json:"response_status" db:"response_status"`
	ResponseTimeMs    *int       `json:"response_time_ms" db:"response_time_ms"`
	RequestSizeBytes  *int       `json:"request_size_bytes" db:"request_size_bytes"`
	ResponseSizeBytes *int       `json:"response_size_bytes" db:"response_size_bytes"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	
	// Joined fields
	APIKey *APIKey `json:"api_key,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	Token               string      `json:"token"`
	ExpiresAt           time.Time   `json:"expires_at"`
	User                SystemUser  `json:"user"`
	ForcePasswordChange bool        `json:"force_password_change"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username  string  `json:"username" validate:"required,min=3,max=50"`
	Email     string  `json:"email" validate:"required,email"`
	RoleID    int     `json:"role_id" validate:"required"`
	FirstName *string `json:"first_name" validate:"omitempty,max=100"`
	LastName  *string `json:"last_name" validate:"omitempty,max=100"`
	Password  *string `json:"password" validate:"omitempty,min=8"` // Optional, will generate if not provided
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email     *string `json:"email" validate:"omitempty,email"`
	RoleID    *int    `json:"role_id"`
	FirstName *string `json:"first_name" validate:"omitempty,max=100"`
	LastName  *string `json:"last_name" validate:"omitempty,max=100"`
	Active    *bool   `json:"active"`
}

// CreateAPIKeyRequest represents a request to create a new API key
type CreateAPIKeyRequest struct {
	KeyName          string         `json:"key_name" validate:"required,min=3,max=100"`
	Description      *string        `json:"description" validate:"omitempty,max=500"`
	Permissions      Permissions    `json:"permissions" validate:"required"`
	ContractAccess   ContractAccess `json:"contract_access"`
	RateLimitPerHour *int           `json:"rate_limit_per_hour" validate:"omitempty,min=1,max=10000"`
	ExpiresAt        *time.Time     `json:"expires_at"`
}

// CreateAPIKeyResponse represents the response when creating an API key
type CreateAPIKeyResponse struct {
	APIKey    APIKey `json:"api_key"`
	PlainKey  string `json:"plain_key"` // Only returned once during creation
}

// UpdateAPIKeyRequest represents a request to update an API key
type UpdateAPIKeyRequest struct {
	KeyName          *string        `json:"key_name" validate:"omitempty,min=3,max=100"`
	Description      *string        `json:"description" validate:"omitempty,max=500"`
	Permissions      *Permissions   `json:"permissions"`
	ContractAccess   *ContractAccess `json:"contract_access"`
	RateLimitPerHour *int           `json:"rate_limit_per_hour" validate:"omitempty,min=1,max=10000"`
	Active           *bool          `json:"active"`
	ExpiresAt        *time.Time     `json:"expires_at"`
}

// AuthContext represents the authentication context for a request
type AuthContext struct {
	UserID      *int        `json:"user_id,omitempty"`
	Username    *string     `json:"username,omitempty"`
	Role        *UserRole   `json:"role,omitempty"`
	APIKeyID    *int        `json:"api_key_id,omitempty"`
	APIKeyName  *string     `json:"api_key_name,omitempty"`
	Permissions Permissions `json:"permissions"`
	IsAPIKey    bool        `json:"is_api_key"`
	SessionID   *string     `json:"session_id,omitempty"`
}

// HasPermission checks if the auth context has permission for a resource and action
func (ac *AuthContext) HasPermission(resource, action string) bool {
	return ac.Permissions.HasPermission(resource, action)
}

// CanAccessContract checks if the auth context can access a specific contract
func (ac *AuthContext) CanAccessContract(contractID int) bool {
	// For user sessions, check if they have read permission on contracts
	if !ac.IsAPIKey {
		return ac.HasPermission("contracts", "read")
	}
	
	// For API keys, this would need to be checked against the API key's contract access
	// This method would need access to the API key data
	return true // Simplified for now
}
