package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/middleware"
	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
)

type CustomerAuthHandler struct {
	authService *services.AuthService
}

func NewCustomerAuthHandler(authService *services.AuthService) *CustomerAuthHandler {
	return &CustomerAuthHandler{
		authService: authService,
	}
}

// CustomerLogin handles customer authentication
func (cah *CustomerAuthHandler) CustomerLogin(w http.ResponseWriter, r *http.Request) {
	var req models.CustomerLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Get client info
	ipAddress := GetClientIP(r)
	userAgent := r.UserAgent()

	response, err := cah.authService.AuthenticateCustomer(req.Email, req.Password, ipAddress, userAgent)
	if err != nil {
		switch err {
		case services.ErrCustomerInvalidCredentials:
			WriteErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", "")
		case services.ErrCustomerLocked:
			WriteErrorResponse(w, http.StatusLocked, "Account locked", "Too many failed login attempts")
		case services.ErrCustomerInactive:
			WriteErrorResponse(w, http.StatusForbidden, "Account inactive", "")
		default:
			WriteErrorResponse(w, http.StatusInternalServerError, "Authentication failed", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, response)
}

// CustomerLogout invalidates the current customer session
func (cah *CustomerAuthHandler) CustomerLogout(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.SessionID == nil {
		WriteErrorResponse(w, http.StatusBadRequest, "No active session", "")
		return
	}

	if err := cah.authService.CustomerLogout(*customerAuthContext.SessionID); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Logout failed", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// ChangeCustomerPassword handles customer password changes
func (cah *CustomerAuthHandler) ChangeCustomerPassword(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.CustomerID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
		return
	}

	var req models.CustomerChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := cah.authService.ChangeCustomerPassword(*customerAuthContext.CustomerID, req.CurrentPassword, req.NewPassword); err != nil {
		if err == services.ErrCustomerInvalidCredentials {
			WriteErrorResponse(w, http.StatusBadRequest, "Current password is incorrect", "")
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Password change failed", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// GetCustomerProfile returns the current customer's profile
func (cah *CustomerAuthHandler) GetCustomerProfile(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.CustomerID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
		return
	}

	customer, err := cah.authService.GetCustomerByID(*customerAuthContext.CustomerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get customer profile", err.Error())
		return
	}

	// Remove sensitive information
	customer.PasswordHash = ""

	WriteJSONResponse(w, http.StatusOK, customer)
}

// GetCustomerDashboard returns dashboard data for the customer
func (cah *CustomerAuthHandler) GetCustomerDashboard(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.CustomerID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
		return
	}

	dashboard, err := cah.authService.GetCustomerDashboard(*customerAuthContext.CustomerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get dashboard", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, dashboard)
}

// GetCustomerContracts returns all contracts for the customer
func (cah *CustomerAuthHandler) GetCustomerContracts(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.CustomerID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
		return
	}

	contracts, err := cah.authService.GetCustomerContracts(*customerAuthContext.CustomerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get contracts", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, contracts)
}

// GetCustomerContract returns a specific contract for the customer
func (cah *CustomerAuthHandler) GetCustomerContract(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.CustomerID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
		return
	}

	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	contract, err := cah.authService.GetCustomerContract(*customerAuthContext.CustomerID, contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, contract)
}

// GetCustomerContractServiceTier returns the service tier for a customer's contract
func (cah *CustomerAuthHandler) GetCustomerContractServiceTier(w http.ResponseWriter, r *http.Request) {
	customerAuthContext := middleware.GetCustomerAuthContext(r)
	if customerAuthContext == nil || customerAuthContext.CustomerID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
		return
	}

	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	serviceTier, err := cah.authService.GetCustomerContractServiceTier(*customerAuthContext.CustomerID, contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Service tier not found", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, serviceTier)
}
