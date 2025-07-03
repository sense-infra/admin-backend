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
	"log"

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
	ErrRoleNotFound           = errors.New("role not found")
	ErrRoleAlreadyExists      = errors.New("role already exists")
	ErrCannotModifySystemRole = errors.New("cannot modify system role")
	ErrCannotDeleteSystemRole = errors.New("cannot delete system role")
	ErrRoleInUse             = errors.New("role is currently assigned to users")
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
		(username, email, password_hash, role_id, first_name, last_name, created_by, force_password_change) 
		VALUES (?, ?, ?, ?, ?, ?, ?, FALSE)`

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

// AdminResetPassword allows admin users to reset any user's password
func (a *AuthService) AdminResetPassword(adminUserID, targetUserID int, newPassword string) error {
	// Verify admin has permission (this should be checked in middleware, but double-check)
	adminUser, err := a.getUserByID(adminUserID)
	if err != nil {
		return fmt.Errorf("failed to get admin user: %w", err)
	}
	
	if !adminUser.Role.Permissions.HasPermission("users", "update") {
		return fmt.Errorf("insufficient permissions to reset user password")
	}

	// Verify target user exists
	targetUser, err := a.getUserByID(targetUserID)
	if err != nil {
		return fmt.Errorf("failed to get target user: %w", err)
	}

	// Prevent admins from changing other admin passwords unless they're super admin
	if targetUser.Role.Name == "admin" && adminUser.Username != "admin" && adminUserID != targetUserID {
		return fmt.Errorf("insufficient permissions to reset admin user password")
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
	
	if _, err := a.db.Exec(query, string(hashedPassword), targetUserID); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all sessions for the target user (force re-login with new password)
	if err := a.invalidateUserSessions(targetUserID); err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}

	return nil
}

// GenerateRandomPasswordForUser generates a random password and sets it for a user (admin only)
func (a *AuthService) GenerateRandomPasswordForUser(adminUserID, targetUserID int) (string, error) {
	// Verify admin has permission
	adminUser, err := a.getUserByID(adminUserID)
	if err != nil {
		return "", fmt.Errorf("failed to get admin user: %w", err)
	}
	
	if !adminUser.Role.Permissions.HasPermission("users", "update") {
		return "", fmt.Errorf("insufficient permissions to reset user password")
	}

	// Generate new password
	newPassword := a.generateRandomPassword()
	
	// Use AdminResetPassword to set the new password
	if err := a.AdminResetPassword(adminUserID, targetUserID, newPassword); err != nil {
		return "", err
	}

	return newPassword, nil
}

// invalidateUserSessions removes all active sessions for a user
func (a *AuthService) invalidateUserSessions(userID int) error {
	query := `DELETE FROM User_Session WHERE user_id = ?`
	if _, err := a.db.Exec(query, userID); err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}
	return nil
}

// GetAllUsers returns all users with their roles
func (a *AuthService) GetAllUsers() ([]*models.SystemUser, error) {
	query := `SELECT u.*, r.name as role_name, r.permissions as role_permissions, r.active as role_active,
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
		var roleActive bool
		var creatorUsername *string

		err := rows.Scan(
			&user.UserID, &user.Username, &user.Email, &user.PasswordHash,
			&user.RoleID, &user.FirstName, &user.LastName, &user.ForcePasswordChange,
			&user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil,
			&user.PasswordChangedAt, &user.Active, &user.CreatedBy,
			&user.CreatedAt, &user.UpdatedAt, &roleName, &rolePermissions,
			&roleActive,
			&creatorUsername,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		user.Role = &models.UserRole{
			RoleID:      user.RoleID,
			Name:        roleName,
			Permissions: rolePermissions,
			Active:      roleActive,
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

// PermanentlyDeleteUser permanently deletes a user from the database
func (a *AuthService) PermanentlyDeleteUser(userID int) error {
	// First revoke all sessions for this user
	sessionQuery := `DELETE FROM User_Session WHERE user_id = ?`
	if _, err := a.db.Exec(sessionQuery, userID); err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	// Then permanently delete the user
	userQuery := `DELETE FROM System_User WHERE user_id = ?`
	result, err := a.db.Exec(userQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Check if user was actually deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user with ID %d not found", userID)
	}

	return nil
}

// UnlockUser unlocks a locked user account
func (a *AuthService) UnlockUser(userID int) error {
	query := `UPDATE System_User 
		SET locked_until = NULL, failed_login_attempts = 0, updated_at = NOW() 
		WHERE user_id = ?`
	
	result, err := a.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user with ID %d not found", userID)
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
	query := `SELECT u.*, r.name as role_name, r.permissions as role_permissions, r.active as role_active
		FROM System_User u
		JOIN User_Role r ON u.role_id = r.role_id
		WHERE u.username = ?`

	var user models.SystemUser
	var roleName string
	var rolePermissions models.Permissions
	var roleActive bool

	err := a.db.QueryRow(query, username).Scan(
		&user.UserID, &user.Username, &user.Email, &user.PasswordHash,
		&user.RoleID, &user.FirstName, &user.LastName, &user.ForcePasswordChange,
		&user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.PasswordChangedAt, &user.Active, &user.CreatedBy,
		&user.CreatedAt, &user.UpdatedAt, &roleName, &rolePermissions, &roleActive,
	)
	if err != nil {
		return nil, err
	}

	// SECURITY FIX: Only assign permissions if role is active
	if roleActive {
		user.Role = &models.UserRole{
			RoleID:      user.RoleID,
			Name:        roleName,
			Permissions: rolePermissions,
			Active:      roleActive,
		}
	} else {
		// Role is inactive - assign empty permissions
		user.Role = &models.UserRole{
			RoleID:      user.RoleID,
			Name:        roleName,
			Permissions: models.Permissions{}, // Empty permissions map
			Active:      roleActive,
		}
	}

	return &user, nil
}

func (a *AuthService) getUserByID(userID int) (*models.SystemUser, error) {
	query := `SELECT u.*, r.name as role_name, r.permissions as role_permissions, r.active as role_active
		FROM System_User u
		JOIN User_Role r ON u.role_id = r.role_id
		WHERE u.user_id = ?`

	var user models.SystemUser
	var roleName string
	var rolePermissions models.Permissions
	var roleActive bool

	err := a.db.QueryRow(query, userID).Scan(
		&user.UserID, &user.Username, &user.Email, &user.PasswordHash,
		&user.RoleID, &user.FirstName, &user.LastName, &user.ForcePasswordChange,
		&user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.PasswordChangedAt, &user.Active, &user.CreatedBy,
		&user.CreatedAt, &user.UpdatedAt, &roleName, &rolePermissions, &roleActive,
	)
	if err != nil {
		return nil, err
	}

	// SECURITY FIX: Only assign permissions if role is active
	if roleActive {
		user.Role = &models.UserRole{
			RoleID:      user.RoleID,
			Name:        roleName,
			Permissions: rolePermissions,
			Active:      roleActive,
		}
	} else {
		// Role is inactive - assign empty permissions
		user.Role = &models.UserRole{
			RoleID:      user.RoleID,
			Name:        roleName,
			Permissions: models.Permissions{}, // Empty permissions map
			Active:      roleActive,
		}
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

// GetRoleByID retrieves a role by its ID
func (s *AuthService) GetRoleByID(roleID int) (*models.UserRole, error) {
	query := `
		SELECT role_id, name, description, permissions, active, created_at, updated_at
		FROM User_Role 
		WHERE role_id = ?
	`
	
	var role models.UserRole
	err := s.db.Get(&role, query, roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	
	return &role, nil
}

// CreateRole creates a new role
func (s *AuthService) CreateRole(req *models.CreateRoleRequest, createdBy *int) (*models.UserRole, error) {
	// Check if role name already exists
	var count int
	err := s.db.Get(&count, "SELECT COUNT(*) FROM User_Role WHERE name = ?", req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check role existence: %w", err)
	}
	if count > 0 {
		return nil, ErrRoleAlreadyExists
	}

	// Set default active status if not provided
	active := true
	if req.Active != nil {
		active = *req.Active
	}

	// Insert the new role
	query := `
		INSERT INTO User_Role (name, description, permissions, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())
	`
	
	result, err := s.db.Exec(query, req.Name, req.Description, req.Permissions, active)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	
	roleID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get role ID: %w", err)
	}
	
	// Return the created role
	return s.GetRoleByID(int(roleID))
}

// UpdateRole updates an existing role
func (s *AuthService) UpdateRole(roleID int, req *models.UpdateRoleRequest) (*models.UserRole, error) {
	// First, get the existing role
	existingRole, err := s.GetRoleByID(roleID)
	if err != nil {
		return nil, err
	}

	// Check if it's a system role that shouldn't be modified
	if s.isSystemRole(existingRole.Name) {
		return nil, ErrCannotModifySystemRole
	}

	// Build update query dynamically
	setParts := []string{}
	args := []interface{}{}

	if req.Name != nil {
		// Check if new name conflicts with existing roles (excluding current role)
		var count int
		err := s.db.Get(&count, "SELECT COUNT(*) FROM User_Role WHERE name = ? AND role_id != ?", *req.Name, roleID)
		if err != nil {
			return nil, fmt.Errorf("failed to check role name conflict: %w", err)
		}
		if count > 0 {
			return nil, ErrRoleAlreadyExists
		}
		setParts = append(setParts, "name = ?")
		args = append(args, *req.Name)
	}

	if req.Description != nil {
		setParts = append(setParts, "description = ?")
		args = append(args, req.Description)
	}

	if req.Permissions != nil {
		setParts = append(setParts, "permissions = ?")
		args = append(args, *req.Permissions)
	}

	if req.Active != nil {
		setParts = append(setParts, "active = ?")
		args = append(args, *req.Active)
	}

	if len(setParts) == 0 {
		// No changes requested, return existing role
		return existingRole, nil
	}

	// Add updated_at and role_id to query
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, roleID)

	query := fmt.Sprintf("UPDATE User_Role SET %s WHERE role_id = ?", strings.Join(setParts, ", "))
	
	_, err = s.db.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	// Return the updated role
	return s.GetRoleByID(roleID)
}

// GetRolesWithStats retrieves all roles with COMPLETE user count statistics (active + inactive)
func (s *AuthService) GetRolesWithStats() ([]models.RoleWithStats, error) {
	query := `
		SELECT
			r.role_id,
			r.name,
			r.description,
			r.permissions,
			r.active,
			r.created_at,
			r.updated_at,
			COALESCE(user_counts.total_user_count, 0) as total_user_count,
			COALESCE(user_counts.active_user_count, 0) as active_user_count,
			COALESCE(user_counts.inactive_user_count, 0) as inactive_user_count
		FROM User_Role r
		LEFT JOIN (
			SELECT 
				role_id, 
				COUNT(*) as total_user_count,
				COUNT(CASE WHEN active = 1 THEN 1 END) as active_user_count,
				COUNT(CASE WHEN active = 0 THEN 1 END) as inactive_user_count
			FROM System_User
			GROUP BY role_id
		) user_counts ON r.role_id = user_counts.role_id
		ORDER BY r.name
	`

	var roles []models.RoleWithStats
	err := s.db.Select(&roles, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles with stats: %w", err)
	}

	return roles, nil
}

// GetRoleUsers retrieves users assigned to a specific role
func (s *AuthService) GetRoleUsers(roleID int) ([]models.UserRoleAssignment, error) {
	// First check if role exists
	_, err := s.GetRoleByID(roleID)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT 
			u.user_id,
			u.username,
			u.email,
			u.first_name,
			u.last_name,
			u.active,
			u.last_login,
			u.created_at
		FROM System_User u
		WHERE u.role_id = ?
		ORDER BY u.username
	`
	
	var users []models.UserRoleAssignment
	err = s.db.Select(&users, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}
	
	return users, nil
}

// Update your existing GetAllRoles method to use GetRolesWithStats:
func (s *AuthService) GetRoles() ([]models.RoleWithStats, error) {
	return s.GetRolesWithStats()
}

// If you have an existing GetAllRoles method, you can replace it or keep both:
func (s *AuthService) GetAllRoles() ([]models.UserRole, error) {
	query := `
		SELECT role_id, name, description, permissions, active, created_at, updated_at
		FROM User_Role 
		ORDER BY name
	`
	
	var roles []models.UserRole
	err := s.db.Select(&roles, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	
	return roles, nil
}

// DeleteRole deletes a role (FIXED VERSION)
func (s *AuthService) DeleteRole(roleID int) error {
	// First, get the role to check if it exists and if it's a system role
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	// Check if it's a system role that shouldn't be deleted
	if s.isSystemRole(role.Name) {
		return ErrCannotDeleteSystemRole
	}

	// Check if any ACTIVE users are assigned to this role
	var userCount int
	err = s.db.Get(&userCount, "SELECT COUNT(*) FROM System_User WHERE role_id = ? AND active = 1", roleID)
	if err != nil {
		return fmt.Errorf("failed to check role usage: %w", err)
	}
	if userCount > 0 {
		return ErrRoleInUse
	}

	// Start a transaction for safe deletion
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete the role
	result, err := tx.Exec("DELETE FROM User_Role WHERE role_id = ?", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Check if role was actually deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrRoleNotFound
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit role deletion: %w", err)
	}

	return nil
}

// GetRoleUsageInfo returns detailed information about role usage (ENHANCED VERSION)
func (s *AuthService) GetRoleUsageInfo(roleID int) (*RoleUsageInfo, error) {
	// Get role details
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return nil, err
	}

	// Get COMPLETE user count statistics (active and inactive)
	var totalUserCount, activeUserCount, inactiveUserCount int

	// Single query to get all counts efficiently
	err = s.db.QueryRow(`
		SELECT 
			COUNT(*) as total_users,
			COUNT(CASE WHEN active = 1 THEN 1 END) as active_users,
			COUNT(CASE WHEN active = 0 THEN 1 END) as inactive_users
		FROM System_User 
		WHERE role_id = ?`, roleID).Scan(&totalUserCount, &activeUserCount, &inactiveUserCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get user counts: %w", err)
	}

	// Get list of ALL users assigned to this role (both active and inactive)
	var users []RoleUser
	err = s.db.Select(&users, `
		SELECT user_id, username, email, first_name, last_name, active, last_login, created_at
		FROM System_User
		WHERE role_id = ?
		ORDER BY active DESC, username`, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}

	return &RoleUsageInfo{
		Role:              *role,
		TotalUserCount:    totalUserCount,    // FIXED: Include total count
		ActiveUserCount:   activeUserCount,
		InactiveUserCount: inactiveUserCount,
		Users:             users,
		CanDelete:         activeUserCount == 0 && !s.isSystemRole(role.Name), // Only check active users for deletion
		IsSystemRole:      s.isSystemRole(role.Name),
	}, nil
}

// RoleUsageInfo represents detailed role usage information (ENHANCED)
type RoleUsageInfo struct {
	Role              models.UserRole `json:"role"`
	TotalUserCount    int             `json:"total_user_count"`     // ADDED: Total users (active + inactive)
	ActiveUserCount   int             `json:"active_user_count"`
	InactiveUserCount int             `json:"inactive_user_count"`
	Users             []RoleUser      `json:"users"`
	CanDelete         bool            `json:"can_delete"`
	IsSystemRole      bool            `json:"is_system_role"`
}

// RoleUser represents a user assigned to a role
type RoleUser struct {
	UserID    int        `json:"user_id" db:"user_id"`
	Username  string     `json:"username" db:"username"`
	Email     string     `json:"email" db:"email"`
	FirstName *string    `json:"first_name" db:"first_name"`
	LastName  *string    `json:"last_name" db:"last_name"`
	Active    bool       `json:"active" db:"active"`
	LastLogin *time.Time `json:"last_login" db:"last_login"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// isSystemRole checks if a role is a system role that shouldn't be modified/deleted
func (s *AuthService) isSystemRole(roleName string) bool {
	systemRoles := []string{"admin", "viewer"}
	for _, systemRole := range systemRoles {
		if strings.ToLower(roleName) == systemRole {
			return true
		}
	}
	return false
}

// DeactivateRole sets a role as inactive instead of deleting it
func (s *AuthService) DeactivateRole(roleID int) error {
	// Get the role first
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	// Check if it's a system role
	if s.isSystemRole(role.Name) {
		return ErrCannotModifySystemRole
	}

	// Deactivate the role
	_, err = s.db.Exec("UPDATE User_Role SET active = FALSE, updated_at = NOW() WHERE role_id = ?", roleID)
	if err != nil {
		return fmt.Errorf("failed to deactivate role: %w", err)
	}

	return nil
}

// ReassignUsersToRole reassigns all users from one role to another
func (s *AuthService) ReassignUsersToRole(fromRoleID, toRoleID int) error {
	// Verify both roles exist
	_, err := s.GetRoleByID(fromRoleID)
	if err != nil {
		return fmt.Errorf("source role not found: %w", err)
	}

	_, err = s.GetRoleByID(toRoleID)
	if err != nil {
		return fmt.Errorf("target role not found: %w", err)
	}

	// Start transaction
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Update all users from the old role to the new role
	result, err := tx.Exec(`
		UPDATE System_User 
		SET role_id = ?, updated_at = NOW() 
		WHERE role_id = ? AND active = 1`, toRoleID, fromRoleID)
	if err != nil {
		return fmt.Errorf("failed to reassign users: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit user reassignment: %w", err)
	}

	log.Printf("Successfully reassigned %d users from role %d to role %d", rowsAffected, fromRoleID, toRoleID)
	return nil
}
