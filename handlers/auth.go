package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

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

// DeleteAPIKey deactivates an API key (admin only) - backward compatibility
func (ah *AuthHandler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	// For backward compatibility, this calls deactivate
	ah.DeactivateAPIKey(w, r)
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

// GetRoles lists all available roles
func (ah *AuthHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := ah.authService.GetAllRoles()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get roles", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, roles)
}
