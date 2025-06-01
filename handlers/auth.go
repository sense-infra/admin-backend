package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
	"github.com/sense-security/api/middleware"
)

// AuthHandler handles authentication requests
type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	response, err := h.authService.AuthenticateUser(
		req.Username, 
		req.Password, 
		GetClientIP(r), 
		r.UserAgent(),
	)
	if err != nil {
		statusCode := http.StatusUnauthorized
		message := "Authentication failed"
		
		switch err {
		case services.ErrInvalidCredentials:
			message = "Invalid username or password"
		case services.ErrUserLocked:
			message = "Account is temporarily locked"
		case services.ErrUserInactive:
			message = "Account is inactive"
		}
		
		WriteErrorResponse(w, statusCode, message, "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, response)
}

// GetProfile returns the current user's profile
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	if authContext.IsAPIKey {
		// For API keys, return limited info
		response := map[string]interface{}{
			"type":         "api_key",
			"api_key_id":   authContext.APIKeyID,
			"api_key_name": authContext.APIKeyName,
			"permissions":  authContext.Permissions,
		}
		WriteJSONResponse(w, http.StatusOK, response)
		return
	}

	// For user sessions, return full user info
	if authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Invalid auth context", "")
		return
	}

	// Use GetAllUsers to get user with role info, then filter by ID
	users, err := h.authService.GetAllUsers()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get user profile", err.Error())
		return
	}

	var user *models.SystemUser
	for _, u := range users {
		if u.UserID == *authContext.UserID {
			user = u
			break
		}
	}

	if user == nil {
		WriteErrorResponse(w, http.StatusNotFound, "User not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, user)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.SessionID == nil {
		WriteErrorResponse(w, http.StatusBadRequest, "No active session", "")
		return
	}

	if err := h.authService.Logout(*authContext.SessionID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to logout", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Logout successful"})
}

// ChangePassword handles password changes
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "User authentication required", "")
		return
	}

	var req models.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.authService.ChangePassword(*authContext.UserID, req.CurrentPassword, req.NewPassword); err != nil {
		statusCode := http.StatusBadRequest
		message := "Failed to change password"
		
		if err == services.ErrInvalidCredentials {
			message = "Current password is incorrect"
		}
		
		WriteErrorResponse(w, statusCode, message, "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// GetUsers returns all users (admin only)
func (h *AuthHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.authService.GetAllUsers()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get users", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, users)
}

// GetUser returns a specific user (admin only)
func (h *AuthHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", err.Error())
		return
	}

	// Use GetAllUsers to get all users with role info, then filter by ID
	users, err := h.authService.GetAllUsers()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get users", err.Error())
		return
	}

	var user *models.SystemUser
	for _, u := range users {
		if u.UserID == userID {
			user = u
			break
		}
	}

	if user == nil {
		WriteErrorResponse(w, http.StatusNotFound, "User not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, user)
}

// CreateUser creates a new user (admin only)
func (h *AuthHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
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

	user, password, err := h.authService.CreateUser(&req, *authContext.UserID)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Failed to create user", err.Error())
		return
	}

	response := map[string]interface{}{
		"user":              user,
		"generated_password": password,
		"message":           "User created successfully",
	}

	WriteJSONResponse(w, http.StatusCreated, response)
}

// UpdateUser updates a user (admin only)
func (h *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", err.Error())
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	user, err := h.authService.UpdateUser(userID, &req)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Failed to update user", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, user)
}

// DeleteUser deletes a user (admin only)
func (h *AuthHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid user ID", err.Error())
		return
	}

	if err := h.authService.DeleteUser(userID); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Failed to delete user", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

// GetRoles returns all roles
func (h *AuthHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.authService.GetAllRoles()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get roles", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, roles)
}

// GetAPIKeys returns all API keys
func (h *AuthHandler) GetAPIKeys(w http.ResponseWriter, r *http.Request) {
	apiKeys, err := h.authService.GetAllAPIKeys()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get API keys", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, apiKeys)
}

// GetAPIKey returns a specific API key
func (h *AuthHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	apiKey, err := h.authService.GetAPIKeyByID(apiKeyID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, apiKey)
}

// CreateAPIKey creates a new API key
func (h *AuthHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "User authentication required", "")
		return
	}

	var req models.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	response, err := h.authService.CreateAPIKey(&req, *authContext.UserID)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Failed to create API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusCreated, response)
}

// UpdateAPIKey updates an API key
func (h *AuthHandler) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	var req models.UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	apiKey, err := h.authService.UpdateAPIKey(apiKeyID, &req)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Failed to update API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, apiKey)
}

// DeleteAPIKey deletes an API key
func (h *AuthHandler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	if err := h.authService.DeleteAPIKey(apiKeyID); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Failed to delete API key", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "API key deleted successfully"})
}

// GetAPIKeyUsage returns usage statistics for an API key
func (h *AuthHandler) GetAPIKeyUsage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	// Get rate limit info
	rateLimitInfo, err := h.authService.GetRateLimitInfo(apiKeyID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get rate limit info", err.Error())
		return
	}

	// Get API key basic info
	apiKey, err := h.authService.GetAPIKeyByID(apiKeyID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	response := map[string]interface{}{
		"api_key_id":     apiKey.APIKeyID,
		"key_name":       apiKey.KeyName,
		"rate_limit":     rateLimitInfo,
		"total_usage":    apiKey.UsageCount,
		"last_used":      apiKey.LastUsed,
		"created_at":     apiKey.CreatedAt,
	}

	WriteJSONResponse(w, http.StatusOK, response)
}
