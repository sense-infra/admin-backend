package services

import (
	"fmt"
	"strings"
	"time"
	"github.com/sense-security/api/models"
)

// Extended methods for AuthService to support the handlers

// GetAllUsers returns all users with their roles
func (a *AuthService) GetAllUsers() ([]*models.SystemUser, error) {
	query := `SELECT u.user_id, u.username, u.email, u.password_hash, u.role_id, 
		u.first_name, u.last_name, u.force_password_change, u.last_login, 
		u.failed_login_attempts, u.locked_until, u.password_changed_at, 
		u.active, u.created_by, u.created_at, u.updated_at,
		r.name as role_name, r.permissions as role_permissions,
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

// GetAllAPIKeys returns all API keys with creator information - COMPLETELY FIXED
func (a *AuthService) GetAllAPIKeys() ([]*models.APIKey, error) {
	// Explicitly list all columns to ensure proper order and mapping
	query := `SELECT 
		ak.api_key_id, ak.key_name, ak.key_hash, ak.key_prefix,
		ak.permissions, ak.contract_access, ak.rate_limit_per_hour, 
		ak.created_by, ak.description, ak.active, ak.last_used, 
		ak.usage_count, ak.expires_at, ak.created_at, ak.updated_at,
		u.username as creator_username
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

		// Scan in the exact same order as the SELECT statement
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

		// Set the creator information
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

// DeactivateAPIKey sets an API key as inactive (keeps the old method for compatibility)
func (a *AuthService) DeactivateAPIKey(apiKeyID int) error {
	query := `UPDATE API_Key SET active = FALSE, updated_at = NOW() WHERE api_key_id = ?`
	if _, err := a.db.Exec(query, apiKeyID); err != nil {
		return fmt.Errorf("failed to deactivate API key: %w", err)
	}
	return nil
}

// PermanentlyDeleteAPIKey actually deletes the API key record from the database
func (a *AuthService) PermanentlyDeleteAPIKey(apiKeyID int) error {
	// First delete usage logs (to maintain referential integrity)
	usageQuery := `DELETE FROM API_Key_Usage_Log WHERE api_key_id = ?`
	if _, err := a.db.Exec(usageQuery, apiKeyID); err != nil {
		return fmt.Errorf("failed to delete API key usage logs: %w", err)
	}

	// Then delete the API key
	query := `DELETE FROM API_Key WHERE api_key_id = ?`
	result, err := a.db.Exec(query, apiKeyID)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("API key not found or already deleted")
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

	// Get usage statistics
	statsQuery := `
		SELECT 
			COUNT(*) as total_requests,
			COUNT(CASE WHEN response_status >= 200 AND response_status < 300 THEN 1 END) as successful_requests,
			COUNT(CASE WHEN response_status >= 400 THEN 1 END) as error_requests,
			AVG(response_time_ms) as avg_response_time,
			MAX(created_at) as last_request,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as requests_last_24h,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as requests_last_7d
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ?`
	
	var stats APIKeyUsageStats
	err = a.db.QueryRow(statsQuery, apiKeyID).Scan(
		&stats.TotalRequests, &stats.SuccessfulRequests, &stats.ErrorRequests,
		&stats.AvgResponseTime, &stats.LastRequest, &stats.RequestsLast24h,
		&stats.RequestsLast7d,
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
	RequestsLast24h     int64         `json:"requests_last_24h"`
	RequestsLast7d      int64         `json:"requests_last_7d"`
}

// GetAPIKeyByID returns an API key by ID (exported version)
func (a *AuthService) GetAPIKeyByID(apiKeyID int) (*models.APIKey, error) {
	return a.getAPIKeyByID(apiKeyID)
}
