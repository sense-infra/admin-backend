package services

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"github.com/sense-security/api/models"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserLocked         = errors.New("user account is locked")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrForcePasswordChange = errors.New("password change required")
	ErrAPIKeyNotFound     = errors.New("API key not found")
	ErrAPIKeyExpired      = errors.New("API key has expired")
	ErrAPIKeyInactive     = errors.New("API key is inactive")
	ErrAPIKeyRateLimited  = errors.New("API key rate limit exceeded")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrSessionExpired     = errors.New("session has expired")
)

type AuthService struct {
	db        *sqlx.DB
	jwtSecret []byte
}

type JWTClaims struct {
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	RoleID    int    `json:"role_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

func NewAuthService(db *sqlx.DB, jwtSecret string) *AuthService {
	return &AuthService{
		db:        db,
		jwtSecret: []byte(jwtSecret),
	}
}

// AuthenticateUser validates user credentials and returns a JWT token
func (a *AuthService) AuthenticateUser(username, password string, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// Get user with role information
	user, err := a.getUserByUsername(username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}

	// Check if user is locked
	if user.IsLocked() {
		return nil, ErrUserLocked
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed login attempts
		a.incrementFailedLoginAttempts(user.UserID)
		return nil, ErrInvalidCredentials
	}

	// Reset failed login attempts on successful login
	if err := a.resetFailedLoginAttempts(user.UserID); err != nil {
		return nil, fmt.Errorf("failed to reset failed login attempts: %w", err)
	}

	// Check if password change is required
	if user.ShouldForcePasswordChange() {
		return &models.LoginResponse{
			User:                *user,
			ForcePasswordChange: true,
		}, nil
	}

	// Create session and JWT token
	sessionID := a.generateSessionID()
	expiresAt := time.Now().Add(24 * time.Hour) // 24 hour sessions

	token, err := a.generateJWT(user.UserID, user.Username, user.RoleID, sessionID, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Store session in database
	tokenHash := a.hashToken(token)
	if err := a.createSession(sessionID, user.UserID, tokenHash, ipAddress, userAgent, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login time
	if err := a.updateLastLogin(user.UserID); err != nil {
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	return &models.LoginResponse{
		Token:               token,
		ExpiresAt:           expiresAt,
		User:                *user,
		ForcePasswordChange: false,
	}, nil
}

// ValidateToken validates a JWT token and returns the auth context
func (a *AuthService) ValidateToken(tokenString string) (*models.AuthContext, error) {
	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check if session exists and is valid
	session, err := a.getSession(claims.SessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionExpired
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	// Verify token hash matches
	tokenHash := a.hashToken(tokenString)
	if session.TokenHash != tokenHash {
		return nil, ErrInvalidToken
	}

	// Get user with role information
	user, err := a.getUserByID(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if !user.Active || user.IsLocked() {
		return nil, ErrUserInactive
	}

	// Update session activity
	if err := a.updateSessionActivity(claims.SessionID); err != nil {
		return nil, fmt.Errorf("failed to update session activity: %w", err)
	}

	return &models.AuthContext{
		UserID:      &user.UserID,
		Username:    &user.Username,
		Role:        user.Role,
		Permissions: user.Role.Permissions,
		IsAPIKey:    false,
		SessionID:   &claims.SessionID,
	}, nil
}

// ValidateAPIKey validates an API key and returns the auth context
func (a *AuthService) ValidateAPIKey(keyString string) (*models.AuthContext, error) {
	// Hash the provided key
	keyHash := a.hashAPIKey(keyString)
	
	// Get API key from database
	apiKey, err := a.getAPIKeyByHash(keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// Check if API key is active
	if !apiKey.Active {
		return nil, ErrAPIKeyInactive
	}

	// Check if API key has expired
	if apiKey.IsExpired() {
		return nil, ErrAPIKeyExpired
	}

	// Check rate limiting - THIS IS THE CRITICAL ADDITION
	if err := a.checkAPIKeyRateLimit(apiKey.APIKeyID, apiKey.RateLimitPerHour); err != nil {
		fmt.Printf("DEBUG: Rate limit check failed: %v\n", err)
		return nil, err
	}

	fmt.Printf("DEBUG: Rate limit check passed\n")

	// Update API key usage
	if err := a.updateAPIKeyUsage(apiKey.APIKeyID); err != nil {
		return nil, fmt.Errorf("failed to update API key usage: %w", err)
	}

	return &models.AuthContext{
		APIKeyID:    &apiKey.APIKeyID,
		APIKeyName:  &apiKey.KeyName,
		Permissions: apiKey.Permissions,
		IsAPIKey:    true,
	}, nil
}

// checkAPIKeyRateLimit checks if the API key has exceeded its rate limit
func (a *AuthService) checkAPIKeyRateLimit(apiKeyID int, rateLimitPerHour int) error {
	// Get usage count for the last hour
	query := `
		SELECT COUNT(*) as usage_last_hour 
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)`
	
	var usageLastHour int
	err := a.db.QueryRow(query, apiKeyID).Scan(&usageLastHour)
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	
	// DEBUG: Add logging
	fmt.Printf("DEBUG: API Key %d - Usage last hour: %d, Rate limit: %d\n", apiKeyID, usageLastHour, rateLimitPerHour)
	
	// Check if usage exceeds the rate limit
	if usageLastHour >= rateLimitPerHour {
		fmt.Printf("DEBUG: Rate limit exceeded for API Key %d\n", apiKeyID)
		return ErrAPIKeyRateLimited
	}
	
	fmt.Printf("DEBUG: Rate limit check passed for API Key %d\n", apiKeyID)
	return nil
}

// GetAPIKeyUsageInLastHour returns the usage count for an API key in the last hour
func (a *AuthService) GetAPIKeyUsageInLastHour(apiKeyID int) (int, error) {
	query := `
		SELECT COUNT(*) as usage_last_hour 
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)`
	
	var usageLastHour int
	err := a.db.QueryRow(query, apiKeyID).Scan(&usageLastHour)
	if err != nil {
		return 0, fmt.Errorf("failed to get usage count: %w", err)
	}
	
	return usageLastHour, nil
}

// ChangePassword changes a user's password
func (a *AuthService) ChangePassword(userID int, currentPassword, newPassword string) error {
	// Get user
	user, err := a.getUserByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password in database
	query := `UPDATE System_User 
		SET password_hash = ?, password_changed_at = NOW(), force_password_change = FALSE 
		WHERE user_id = ?`
	
	if _, err := a.db.Exec(query, string(hashedPassword), userID); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// Logout invalidates a session
func (a *AuthService) Logout(sessionID string) error {
	query := `DELETE FROM User_Session WHERE session_id = ?`
	if _, err := a.db.Exec(query, sessionID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// CreateUser creates a new user account
func (a *AuthService) CreateUser(req *models.CreateUserRequest, createdBy int) (*models.SystemUser, string, error) {
	// Generate password if not provided
	password := ""
	if req.Password != nil {
		password = *req.Password
	} else {
		password = a.generateRandomPassword()
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Insert user
	query := `INSERT INTO System_User 
		(username, email, password_hash, role_id, first_name, last_name, created_by) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	
	result, err := a.db.Exec(query, req.Username, req.Email, string(hashedPassword), 
		req.RoleID, req.FirstName, req.LastName, createdBy)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user ID: %w", err)
	}

	// Get created user
	user, err := a.getUserByID(int(userID))
	if err != nil {
		return nil, "", fmt.Errorf("failed to get created user: %w", err)
	}

	return user, password, nil
}

// CreateAPIKey creates a new API key
func (a *AuthService) CreateAPIKey(req *models.CreateAPIKeyRequest, createdBy int) (*models.CreateAPIKeyResponse, error) {
	// Generate API key
	keyString := a.generateAPIKey()
	keyHash := a.hashAPIKey(keyString)
	keyPrefix := keyString[:8] // First 8 characters for identification

	// Set default rate limit if not provided
	rateLimit := 1000
	if req.RateLimitPerHour != nil {
		rateLimit = *req.RateLimitPerHour
	}

	// Insert API key
	query := `INSERT INTO API_Key 
		(key_name, key_hash, key_prefix, permissions, contract_access, 
		 rate_limit_per_hour, created_by, description, expires_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	result, err := a.db.Exec(query, req.KeyName, keyHash, keyPrefix,
		req.Permissions, req.ContractAccess, rateLimit, createdBy, 
		req.Description, req.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	apiKeyID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get API key ID: %w", err)
	}

	// Get created API key
	apiKey, err := a.getAPIKeyByID(int(apiKeyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get created API key: %w", err)
	}

	return &models.CreateAPIKeyResponse{
		APIKey:   *apiKey,
		PlainKey: keyString,
	}, nil
}

// LogAPIUsage logs API key usage
func (a *AuthService) LogAPIUsage(apiKeyID int, endpoint, method, ipAddress, userAgent string, 
	responseStatus, responseTimeMs, requestSize, responseSize int) error {
	
	query := `INSERT INTO API_Key_Usage_Log 
		(api_key_id, endpoint, method, ip_address, user_agent, response_status, 
		 response_time_ms, request_size_bytes, response_size_bytes) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err := a.db.Exec(query, apiKeyID, endpoint, method, ipAddress, userAgent,
		responseStatus, responseTimeMs, requestSize, responseSize)
	if err != nil {
		return fmt.Errorf("failed to log API usage: %w", err)
	}

	return nil
}

// ==== EXTENDED METHODS FROM auth_extended.go ====

// GetAllUsers returns all users with their roles
func (a *AuthService) GetAllUsers() ([]*models.SystemUser, error) {
	query := `SELECT u.*, r.name as role_name, r.permissions as role_permissions,
		creator.username as creator_username
		FROM System_User u 
		JOIN User_Role r ON u.role_id = r.role_id 
		LEFT JOIN System_User creator ON u.created_by = creator.user_id
		ORDER BY u.created_at DESC`
	
	rows, err := a.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*models.SystemUser
	for rows.Next() {
		var user models.SystemUser
		var roleName string
		var rolePermissions models.Permissions
		var creatorUsername *string

		err := rows.Scan(
			&user.UserID, &user.Username, &user.Email, &user.PasswordHash,
			&user.RoleID, &user.FirstName, &user.LastName, &user.ForcePasswordChange,
			&user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil,
			&user.PasswordChangedAt, &user.Active, &user.CreatedBy,
			&user.CreatedAt, &user.UpdatedAt, &roleName, &rolePermissions,
			&creatorUsername,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		user.Role = &models.UserRole{
			RoleID:      user.RoleID,
			Name:        roleName,
			Permissions: rolePermissions,
		}

		if creatorUsername != nil {
			user.Creator = &models.SystemUser{Username: *creatorUsername}
		}

		users = append(users, &user)
	}

	return users, nil
}

// GetUserByID returns a user by ID with role information
func (a *AuthService) GetUserByID(userID int) (*models.SystemUser, error) {
	return a.getUserByID(userID)
}

// UpdateUser updates a user's information
func (a *AuthService) UpdateUser(userID int, req *models.UpdateUserRequest) (*models.SystemUser, error) {
	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}
	
	if req.Email != nil {
		setParts = append(setParts, "email = ?")
		args = append(args, *req.Email)
	}
	if req.RoleID != nil {
		setParts = append(setParts, "role_id = ?")
		args = append(args, *req.RoleID)
	}
	if req.FirstName != nil {
		setParts = append(setParts, "first_name = ?")
		args = append(args, *req.FirstName)
	}
	if req.LastName != nil {
		setParts = append(setParts, "last_name = ?")
		args = append(args, *req.LastName)
	}
	if req.Active != nil {
		setParts = append(setParts, "active = ?")
		args = append(args, *req.Active)
	}

	if len(setParts) == 0 {
		return a.GetUserByID(userID) // No changes, return current user
	}

	// Add updated_at
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, userID)

	query := fmt.Sprintf("UPDATE System_User SET %s WHERE user_id = ?", 
		strings.Join(setParts, ", "))
	
	if _, err := a.db.Exec(query, args...); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return a.GetUserByID(userID)
}

// DeactivateUser sets a user as inactive
func (a *AuthService) DeactivateUser(userID int) error {
	query := `UPDATE System_User SET active = FALSE, updated_at = NOW() WHERE user_id = ?`
	if _, err := a.db.Exec(query, userID); err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	// Invalidate all sessions for this user
	sessionQuery := `DELETE FROM User_Session WHERE user_id = ?`
	if _, err := a.db.Exec(sessionQuery, userID); err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}

	return nil
}

// GetAllAPIKeys returns all API keys with creator information
func (a *AuthService) GetAllAPIKeys() ([]*models.APIKey, error) {
	query := `SELECT ak.*, u.username as creator_username
		FROM API_Key ak 
		LEFT JOIN System_User u ON ak.created_by = u.user_id
		ORDER BY ak.created_at DESC`
	
	rows, err := a.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query API keys: %w", err)
	}
	defer rows.Close()

	var apiKeys []*models.APIKey
	for rows.Next() {
		var apiKey models.APIKey
		var creatorUsername *string

		err := rows.Scan(
			&apiKey.APIKeyID, &apiKey.KeyName, &apiKey.KeyHash, &apiKey.KeyPrefix,
			&apiKey.Permissions, &apiKey.ContractAccess, &apiKey.RateLimitPerHour,
			&apiKey.CreatedBy, &apiKey.Description, &apiKey.Active,
			&apiKey.LastUsed, &apiKey.UsageCount, &apiKey.ExpiresAt,
			&apiKey.CreatedAt, &apiKey.UpdatedAt, &creatorUsername,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan API key: %w", err)
		}

		if creatorUsername != nil {
			apiKey.Creator = &models.SystemUser{Username: *creatorUsername}
		}

		apiKeys = append(apiKeys, &apiKey)
	}

	return apiKeys, nil
}

// UpdateAPIKey updates an API key's information
func (a *AuthService) UpdateAPIKey(apiKeyID int, req *models.UpdateAPIKeyRequest) (*models.APIKey, error) {
	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}
	
	if req.KeyName != nil {
		setParts = append(setParts, "key_name = ?")
		args = append(args, *req.KeyName)
	}
	if req.Description != nil {
		setParts = append(setParts, "description = ?")
		args = append(args, *req.Description)
	}
	if req.Permissions != nil {
		setParts = append(setParts, "permissions = ?")
		args = append(args, *req.Permissions)
	}
	if req.ContractAccess != nil {
		setParts = append(setParts, "contract_access = ?")
		args = append(args, *req.ContractAccess)
	}
	if req.RateLimitPerHour != nil {
		setParts = append(setParts, "rate_limit_per_hour = ?")
		args = append(args, *req.RateLimitPerHour)
	}
	if req.Active != nil {
		setParts = append(setParts, "active = ?")
		args = append(args, *req.Active)
	}
	if req.ExpiresAt != nil {
		setParts = append(setParts, "expires_at = ?")
		args = append(args, *req.ExpiresAt)
	}

	if len(setParts) == 0 {
		return a.getAPIKeyByID(apiKeyID) // No changes, return current API key
	}

	// Add updated_at
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, apiKeyID)

	query := fmt.Sprintf("UPDATE API_Key SET %s WHERE api_key_id = ?", 
		strings.Join(setParts, ", "))
	
	if _, err := a.db.Exec(query, args...); err != nil {
		return nil, fmt.Errorf("failed to update API key: %w", err)
	}

	return a.getAPIKeyByID(apiKeyID)
}

// DeactivateAPIKey sets an API key as inactive
func (a *AuthService) DeactivateAPIKey(apiKeyID int) error {
	query := `UPDATE API_Key SET active = FALSE, updated_at = NOW() WHERE api_key_id = ?`
	if _, err := a.db.Exec(query, apiKeyID); err != nil {
		return fmt.Errorf("failed to deactivate API key: %w", err)
	}
	return nil
}

// PermanentlyDeleteAPIKey permanently deletes an API key (for auth handler compatibility)
func (a *AuthService) PermanentlyDeleteAPIKey(apiKeyID int) error {
	// First delete all usage logs
	logQuery := `DELETE FROM API_Key_Usage_Log WHERE api_key_id = ?`
	if _, err := a.db.Exec(logQuery, apiKeyID); err != nil {
		return fmt.Errorf("failed to delete API key usage logs: %w", err)
	}

	// Then delete the API key
	keyQuery := `DELETE FROM API_Key WHERE api_key_id = ?`
	if _, err := a.db.Exec(keyQuery, apiKeyID); err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	
	return nil
}

// GetAPIKeyUsage returns usage statistics for an API key
func (a *AuthService) GetAPIKeyUsage(apiKeyID int) (*APIKeyUsageStats, error) {
	// Get basic API key info
	apiKey, err := a.getAPIKeyByID(apiKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// Get usage statistics including last hour usage
	statsQuery := `
		SELECT 
			COUNT(*) as total_requests,
			COUNT(CASE WHEN response_status >= 200 AND response_status < 300 THEN 1 END) as successful_requests,
			COUNT(CASE WHEN response_status >= 400 THEN 1 END) as error_requests,
			AVG(response_time_ms) as avg_response_time,
			MAX(created_at) as last_request,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as requests_last_hour,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as requests_last_24h,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as requests_last_7d
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ?`
	
	var stats APIKeyUsageStats
	err = a.db.QueryRow(statsQuery, apiKeyID).Scan(
		&stats.TotalRequests, &stats.SuccessfulRequests, &stats.ErrorRequests,
		&stats.AvgResponseTime, &stats.LastRequest, &stats.RequestsLastHour,
		&stats.RequestsLast24h, &stats.RequestsLast7d,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}

	stats.APIKey = *apiKey
	return &stats, nil
}

// GetAllRoles returns all available roles
func (a *AuthService) GetAllRoles() ([]*models.UserRole, error) {
	query := `SELECT * FROM User_Role WHERE active = TRUE ORDER BY name`
	
	var roles []*models.UserRole
	err := a.db.Select(&roles, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	return roles, nil
}

// APIKeyUsageStats represents usage statistics for an API key
type APIKeyUsageStats struct {
	APIKey              models.APIKey `json:"api_key"`
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	ErrorRequests       int64         `json:"error_requests"`
	AvgResponseTime     *float64      `json:"avg_response_time_ms"`
	LastRequest         *time.Time    `json:"last_request"`
	RequestsLastHour    int64         `json:"requests_last_hour"`  // THIS IS THE KEY ADDITION
	RequestsLast24h     int64         `json:"requests_last_24h"`
	RequestsLast7d      int64         `json:"requests_last_7d"`
}

// GetAPIKeyByID returns an API key by ID (exported version)
func (a *AuthService) GetAPIKeyByID(apiKeyID int) (*models.APIKey, error) {
	return a.getAPIKeyByID(apiKeyID)
}

// Helper methods

func (a *AuthService) getUserByUsername(username string) (*models.SystemUser, error) {
	query := `SELECT u.*, r.name as role_name, r.permissions as role_permissions
		FROM System_User u 
		JOIN User_Role r ON u.role_id = r.role_id 
		WHERE u.username = ?`
	
	var user models.SystemUser
	var roleName string
	var rolePermissions models.Permissions
	
	err := a.db.QueryRow(query, username).Scan(
		&user.UserID, &user.Username, &user.Email, &user.PasswordHash,
		&user.RoleID, &user.FirstName, &user.LastName, &user.ForcePasswordChange,
		&user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.PasswordChangedAt, &user.Active, &user.CreatedBy,
		&user.CreatedAt, &user.UpdatedAt, &roleName, &rolePermissions,
	)
	if err != nil {
		return nil, err
	}

	user.Role = &models.UserRole{
		RoleID:      user.RoleID,
		Name:        roleName,
		Permissions: rolePermissions,
	}

	return &user, nil
}

func (a *AuthService) getUserByID(userID int) (*models.SystemUser, error) {
	query := `SELECT u.*, r.name as role_name, r.permissions as role_permissions
		FROM System_User u 
		JOIN User_Role r ON u.role_id = r.role_id 
		WHERE u.user_id = ?`
	
	var user models.SystemUser
	var roleName string
	var rolePermissions models.Permissions
	
	err := a.db.QueryRow(query, userID).Scan(
		&user.UserID, &user.Username, &user.Email, &user.PasswordHash,
		&user.RoleID, &user.FirstName, &user.LastName, &user.ForcePasswordChange,
		&user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.PasswordChangedAt, &user.Active, &user.CreatedBy,
		&user.CreatedAt, &user.UpdatedAt, &roleName, &rolePermissions,
	)
	if err != nil {
		return nil, err
	}

	user.Role = &models.UserRole{
		RoleID:      user.RoleID,
		Name:        roleName,
		Permissions: rolePermissions,
	}

	return &user, nil
}

func (a *AuthService) getAPIKeyByHash(keyHash string) (*models.APIKey, error) {
	query := `SELECT * FROM API_Key WHERE key_hash = ?`
	
	var apiKey models.APIKey
	err := a.db.Get(&apiKey, query, keyHash)
	return &apiKey, err
}

func (a *AuthService) getAPIKeyByID(apiKeyID int) (*models.APIKey, error) {
	query := `SELECT * FROM API_Key WHERE api_key_id = ?`
	
	var apiKey models.APIKey
	err := a.db.Get(&apiKey, query, apiKeyID)
	return &apiKey, err
}

func (a *AuthService) getSession(sessionID string) (*models.UserSession, error) {
	query := `SELECT * FROM User_Session WHERE session_id = ?`
	
	var session models.UserSession
	err := a.db.Get(&session, query, sessionID)
	return &session, err
}

func (a *AuthService) createSession(sessionID string, userID int, tokenHash, ipAddress, userAgent string, expiresAt time.Time) error {
	query := `INSERT INTO User_Session 
		(session_id, user_id, token_hash, ip_address, user_agent, expires_at) 
		VALUES (?, ?, ?, ?, ?, ?)`
	
	_, err := a.db.Exec(query, sessionID, userID, tokenHash, ipAddress, userAgent, expiresAt)
	return err
}

func (a *AuthService) updateSessionActivity(sessionID string) error {
	query := `UPDATE User_Session SET last_activity = NOW() WHERE session_id = ?`
	_, err := a.db.Exec(query, sessionID)
	return err
}

func (a *AuthService) updateLastLogin(userID int) error {
	query := `UPDATE System_User SET last_login = NOW() WHERE user_id = ?`
	_, err := a.db.Exec(query, userID)
	return err
}

func (a *AuthService) incrementFailedLoginAttempts(userID int) error {
	query := `UPDATE System_User 
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE 
		        WHEN failed_login_attempts >= 4 THEN DATE_ADD(NOW(), INTERVAL 30 MINUTE)
		        ELSE locked_until 
		    END
		WHERE user_id = ?`
	_, err := a.db.Exec(query, userID)
	return err
}

func (a *AuthService) resetFailedLoginAttempts(userID int) error {
	query := `UPDATE System_User 
		SET failed_login_attempts = 0, locked_until = NULL 
		WHERE user_id = ?`
	_, err := a.db.Exec(query, userID)
	return err
}

func (a *AuthService) updateAPIKeyUsage(apiKeyID int) error {
	query := `UPDATE API_Key 
		SET last_used = NOW(), usage_count = usage_count + 1 
		WHERE api_key_id = ?`
	_, err := a.db.Exec(query, apiKeyID)
	return err
}

func (a *AuthService) generateJWT(userID int, username string, roleID int, sessionID string, expiresAt time.Time) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		Username:  username,
		RoleID:    roleID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        sessionID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

func (a *AuthService) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (a *AuthService) generateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "sg_" + base64.URLEncoding.EncodeToString(bytes)
}

func (a *AuthService) generateRandomPassword() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:12] + "!"
}

func (a *AuthService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (a *AuthService) hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}
