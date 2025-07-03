package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"fmt"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/middleware"
	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Login handles user authentication
func (ah *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Get client info
	ipAddress := GetClientIP(r)
	userAgent := r.UserAgent()

	response, err := ah.authService.AuthenticateUser(req.Username, req.Password, ipAddress, userAgent)
	if err != nil {
		switch err {
		case services.ErrInvalidCredentials:
			WriteErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", "")
		case services.ErrUserLocked:
			WriteErrorResponse(w, http.StatusLocked, "Account locked", "Too many failed login attempts")
		case services.ErrUserInactive:
			WriteErrorResponse(w, http.StatusForbidden, "Account inactive", "")
		default:
			WriteErrorResponse(w, http.StatusInternalServerError, "Authentication failed", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, response)
}

// Logout invalidates the current session
func (ah *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.SessionID == nil {
		WriteErrorResponse(w, http.StatusBadRequest, "No active session", "")
		return
	}

	if err := ah.authService.Logout(*authContext.SessionID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Logout failed", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// ChangePassword handles password changes
func (ah *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	var req models.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := ah.authService.ChangePassword(*authContext.UserID, req.CurrentPassword, req.NewPassword); err != nil {
		if err == services.ErrInvalidCredentials {
			WriteErrorResponse(w, http.StatusBadRequest, "Current password is incorrect", "")
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Password change failed", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// AdminResetPassword allows admin users to reset any user's password
func (ah *AuthHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	// Check if user has permission to update users
	if !authContext.HasPermission("users", "update") {
		WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "")
		return
	}

	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	var req struct {
		NewPassword string `json:"new_password" validate:"required,min=8"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := ah.authService.AdminResetPassword(*authContext.UserID, userID, req.NewPassword); err != nil {
		if strings.Contains(err.Error(), "insufficient permissions") {
			WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", err.Error())
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to reset password", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// AdminGeneratePassword generates a random password for a user (admin only)
func (ah *AuthHandler) AdminGeneratePassword(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	// Check if user has permission to update users
	if !authContext.HasPermission("users", "update") {
		WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "")
		return
	}

	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	newPassword, err := ah.authService.GenerateRandomPasswordForUser(*authContext.UserID, userID)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient permissions") {
			WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", err.Error())
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to generate password", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":      "Password generated successfully",
		"new_password": newPassword,
	})
}

// GetCurrentUserProfile returns the current user's profile with additional information
func (ah *AuthHandler) GetCurrentUserProfile(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	user, err := ah.authService.GetUserByID(*authContext.UserID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get user profile", err.Error())
		return
	}

	// Remove sensitive information
	user.PasswordHash = ""

	WriteJSONResponse(w, http.StatusOK, user)
}

// UpdateCurrentUserProfile allows users to update their own profile
func (ah *AuthHandler) UpdateCurrentUserProfile(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	var req struct {
		Email     *string `json:"email" validate:"omitempty,email"`
		FirstName *string `json:"first_name" validate:"omitempty,max=100"`
		LastName  *string `json:"last_name" validate:"omitempty,max=100"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Convert to UpdateUserRequest (users can't change their own role or active status)
	updateReq := &models.UpdateUserRequest{
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	user, err := ah.authService.UpdateUser(*authContext.UserID, updateReq)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update profile", err.Error())
		return
	}

	// Remove sensitive information
	user.PasswordHash = ""

	WriteJSONResponse(w, http.StatusOK, user)
}

// GetProfile returns the current user's profile
func (ah *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, authContext)
}

// CreateUser creates a new user (admin only)
func (ah *AuthHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	var req models.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	user, password, err := ah.authService.CreateUser(&req, *authContext.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			WriteErrorResponse(w, http.StatusConflict, "User already exists", "Username or email already in use")
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create user", err.Error())
		}
		return
	}

	response := map[string]interface{}{
		"user":     user,
		"password": password, // Only returned during creation
		"message":  "User created successfully. Please provide the temporary password to the user.",
	}

	WriteJSONResponse(w, http.StatusCreated, response)
}

// GetUsers lists all users (admin only)
func (ah *AuthHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ah.authService.GetAllUsers()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get users", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, users)
}

// GetUser gets a specific user by ID (admin only)
func (ah *AuthHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	user, err := ah.authService.GetUserByID(userID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "User not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, user)
}

// UpdateUser updates a user (admin only)
func (ah *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	user, err := ah.authService.UpdateUser(userID, &req)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update user", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, user)
}

// DeleteUser deactivates a user (admin only)
func (ah *AuthHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	if err := ah.authService.DeactivateUser(userID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to deactivate user", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "User deactivated successfully"})
}

// PermanentlyDeleteUser permanently deletes a user (admin only)
func (ah *AuthHandler) PermanentlyDeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	if err := ah.authService.PermanentlyDeleteUser(userID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to permanently delete user", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "User permanently deleted successfully"})
}

// UnlockUser unlocks a locked user account (admin only)
func (ah *AuthHandler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", "")
		return
	}

	if err := ah.authService.UnlockUser(userID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to unlock user", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "User unlocked successfully"})
}

// CreateAPIKey creates a new API key (admin only)
func (ah *AuthHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	var req models.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	response, err := ah.authService.CreateAPIKey(&req, *authContext.UserID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusCreated, response)
}

// GetAPIKeys lists all API keys (admin only)
func (ah *AuthHandler) GetAPIKeys(w http.ResponseWriter, r *http.Request) {
	apiKeys, err := ah.authService.GetAllAPIKeys()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get API keys", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, apiKeys)
}

// GetAPIKey gets a specific API key by ID (admin only)
func (ah *AuthHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", "")
		return
	}

	apiKey, err := ah.authService.GetAPIKeyByID(apiKeyID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "API key not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, apiKey)
}

// UpdateAPIKey updates an API key (admin only)
func (ah *AuthHandler) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", "")
		return
	}

	var req models.UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	apiKey, err := ah.authService.UpdateAPIKey(apiKeyID, &req)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, apiKey)
}

// DeactivateAPIKey sets an API key as inactive (admin only)
func (ah *AuthHandler) DeactivateAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", "")
		return
	}

	if err := ah.authService.DeactivateAPIKey(apiKeyID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to deactivate API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "API key deactivated successfully"})
}

// PermanentlyDeleteAPIKey completely removes an API key from the database (admin only)
func (ah *AuthHandler) PermanentlyDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", "")
		return
	}

	if err := ah.authService.PermanentlyDeleteAPIKey(apiKeyID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			WriteErrorResponse(w, http.StatusNotFound, "API key not found", "")
			return
		}
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to permanently delete API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "API key permanently deleted successfully"})
}

// GetAPIKeyUsage gets usage statistics for an API key (admin only)
func (ah *AuthHandler) GetAPIKeyUsage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", "")
		return
	}

	usage, err := ah.authService.GetAPIKeyUsage(apiKeyID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get API key usage", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, usage)
}

// GetRoles lists all available roles with COMPLETE stats
func (ah *AuthHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	// DEBUG: Add logging to see what's happening
	authContext := middleware.GetAuthContext(r)
	log.Printf("🔍 GetRoles called by user: %v", authContext)

	if authContext != nil {
		log.Printf("🔍 User ID: %v", authContext.UserID)
		log.Printf("🔍 Username: %v", authContext.Username)
		log.Printf("🔍 Role: %v", authContext.Role)
		log.Printf("🔍 Permissions: %v", authContext.Permissions)
		log.Printf("🔍 Has roles:read permission: %v", authContext.HasPermission("roles", "read"))
	} else {
		log.Printf("❌ No auth context found")
	}

	// Use the enhanced method that returns complete user statistics
	roles, err := ah.authService.GetRolesWithStats()
	if err != nil {
		log.Printf("❌ Failed to get roles from service: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get roles", err.Error())
		return
	}

	log.Printf("✅ Successfully retrieved %d roles with complete user stats", len(roles))
	
	// DEBUG: Log the user counts for verification
	for _, role := range roles {
		log.Printf("📊 Role '%s': Total=%d, Active=%d, Inactive=%d", 
			role.Name, role.TotalUserCount, role.ActiveUserCount, role.InactiveUserCount)
	}

	WriteJSONResponse(w, http.StatusOK, roles)
}

// GetRole retrieves a specific role by ID
func (ah *AuthHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]
	
	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	role, err := ah.authService.GetRoleByID(roleID)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		log.Printf("Failed to get role: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve role", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, role)
}

// CreateRole creates a new role
func (ah *AuthHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req models.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Basic validation
	if req.Name == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Role name is required", "")
		return
	}

	if len(req.Permissions) == 0 {
		WriteErrorResponse(w, http.StatusBadRequest, "At least one permission is required", "")
		return
	}

	// Get the current user for audit logging
	authContext := middleware.GetAuthContext(r)
	var createdBy *int
	if authContext != nil && authContext.UserID != nil {
		createdBy = authContext.UserID
	}

	role, err := ah.authService.CreateRole(&req, createdBy)
	if err != nil {
		if err == services.ErrRoleAlreadyExists {
			WriteErrorResponse(w, http.StatusConflict, "Role already exists", "")
			return
		}
		log.Printf("Failed to create role: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create role", "")
		return
	}

	WriteJSONResponse(w, http.StatusCreated, role)
}

// UpdateRole updates an existing role
func (ah *AuthHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]
	
	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	var req models.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	role, err := ah.authService.UpdateRole(roleID, &req)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		if err == services.ErrCannotModifySystemRole {
			WriteErrorResponse(w, http.StatusForbidden, "Cannot modify system role", "")
			return
		}
		log.Printf("Failed to update role: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update role", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, role)
}

// GetRoleUsers retrieves users assigned to a specific role
func (ah *AuthHandler) GetRoleUsers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]
	
	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	users, err := ah.authService.GetRoleUsers(roleID)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		log.Printf("Failed to get role users: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve role users", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, users)
}

// DeleteRole deletes a role (ENHANCED VERSION)
func (ah *AuthHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]

	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	// Get detailed role usage information first
	usageInfo, err := ah.authService.GetRoleUsageInfo(roleID)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		log.Printf("Failed to get role usage info: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve role information", "")
		return
	}

	// Check if role can be deleted
	if !usageInfo.CanDelete {
		var reason string
		if usageInfo.IsSystemRole {
			reason = "Cannot delete system role"
		} else if usageInfo.ActiveUserCount > 0 {
			reason = fmt.Sprintf("Cannot delete role that is assigned to %d active users", usageInfo.ActiveUserCount)
		} else {
			reason = "Role cannot be deleted"
		}

		WriteErrorResponse(w, http.StatusConflict, reason, "")
		return
	}

	// Perform the deletion
	err = ah.authService.DeleteRole(roleID)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		if err == services.ErrCannotDeleteSystemRole {
			WriteErrorResponse(w, http.StatusForbidden, "Cannot delete system role", "")
			return
		}
		if err == services.ErrRoleInUse {
			WriteErrorResponse(w, http.StatusConflict, "Cannot delete role that is assigned to users", "")
			return
		}
		log.Printf("Failed to delete role: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete role", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Role deleted successfully",
	})
}

// GetRoleUsage returns detailed role usage information
func (ah *AuthHandler) GetRoleUsage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]

	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	usageInfo, err := ah.authService.GetRoleUsageInfo(roleID)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		log.Printf("Failed to get role usage info: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve role usage information", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, usageInfo)
}

// DeactivateRole deactivates a role instead of deleting it
func (ah *AuthHandler) DeactivateRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]

	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	err = ah.authService.DeactivateRole(roleID)
	if err != nil {
		if err == services.ErrRoleNotFound {
			WriteErrorResponse(w, http.StatusNotFound, "Role not found", "")
			return
		}
		if err == services.ErrCannotModifySystemRole {
			WriteErrorResponse(w, http.StatusForbidden, "Cannot modify system role", "")
			return
		}
		log.Printf("Failed to deactivate role: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to deactivate role", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Role deactivated successfully",
	})
}

// ReassignRoleUsers reassigns users from one role to another
func (ah *AuthHandler) ReassignRoleUsers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleIDStr := vars["id"]

	roleID, err := strconv.Atoi(roleIDStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid role ID", "")
		return
	}

	var req struct {
		NewRoleID int `json:"new_role_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if roleID == req.NewRoleID {
		WriteErrorResponse(w, http.StatusBadRequest, "Source and target roles cannot be the same", "")
		return
	}

	err = ah.authService.ReassignUsersToRole(roleID, req.NewRoleID)
	if err != nil {
		log.Printf("Failed to reassign users: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to reassign users", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Users reassigned successfully",
	})
}
