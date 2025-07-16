package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	"github.com/sense-security/api/middleware"
	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
)

// CustomerHandler handles customer-related requests
type CustomerHandler struct {
	*BaseHandler
}

func NewCustomerHandler(database *sqlx.DB) *CustomerHandler {
	return &CustomerHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// GetCustomers returns a list of all customers
func (ch *CustomerHandler) GetCustomers(w http.ResponseWriter, r *http.Request) {
	query := `SELECT customer_id, name_on_contract, address, unique_id, email, phone_number,
		force_password_change, last_login, failed_login_attempts, locked_until, 
		password_changed_at, active, created_at, updated_at 
		FROM Customer ORDER BY created_at DESC`

	var customers []models.Customer
	err := ch.db.Select(&customers, query)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve customers", err.Error())
		return
	}

	// Remove password hashes from response
	for i := range customers {
		customers[i].PasswordHash = ""
	}

	WriteJSONResponse(w, http.StatusOK, customers)
}

// GetCustomer returns a specific customer by ID
func (ch *CustomerHandler) GetCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "Customer ID must be a number")
		return
	}

	query := `SELECT customer_id, name_on_contract, address, unique_id, email, phone_number,
		force_password_change, last_login, failed_login_attempts, locked_until, 
		password_changed_at, active, created_at, updated_at 
		FROM Customer WHERE customer_id = ?`

	var customer models.Customer
	err = ch.db.Get(&customer, query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

	// Remove password hash from response
	customer.PasswordHash = ""

	WriteJSONResponse(w, http.StatusOK, customer)
}

// GetCustomerWithContracts returns a customer with their assigned contracts
func (ch *CustomerHandler) GetCustomerWithContracts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "Customer ID must be a number")
		return
	}

	// Get customer basic info
	query := `SELECT customer_id, name_on_contract, address, unique_id, email, phone_number,
		created_at, updated_at FROM Customer WHERE customer_id = ?`

	var customerWithContracts models.CustomerWithContracts
	err = ch.db.Get(&customerWithContracts, query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

	// Get customer's contracts
	contractQuery := `
		SELECT 
			c.contract_id, 
			c.service_address, 
			c.start_date, 
			c.end_date,
			st.name as service_tier_name
		FROM Contract c
		JOIN Contract_Customer_Mapping ccm ON c.contract_id = ccm.contract_id
		LEFT JOIN Contract_Service_Tier cst ON c.contract_id = cst.contract_id 
			AND cst.start_date <= CURDATE() 
			AND cst.end_date >= CURDATE()
		LEFT JOIN Service_Tier st ON cst.service_tier_id = st.service_tier_id
		WHERE ccm.customer_id = ?
		ORDER BY c.start_date DESC`

	err = ch.db.Select(&customerWithContracts.Contracts, contractQuery, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get customer contracts", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, customerWithContracts)
}

// CreateCustomer creates a new customer
func (ch *CustomerHandler) CreateCustomer(w http.ResponseWriter, r *http.Request) {
	var req models.CreateCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate required fields
	if req.NameOnContract == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required field", "name_on_contract is required")
		return
	}

	if req.Address == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required field", "address is required")
		return
	}

	if req.UniqueID == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required field", "unique_id is required")
		return
	}

	if req.Password == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required field", "password is required")
		return
	}

	if len(req.Password) < 8 {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid password", "password must be at least 8 characters")
		return
	}

	// Set default active status
	active := true
	if req.Active != nil {
		active = *req.Active
	}

	// Hash the provided password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to process password", err.Error())
		return
	}

	// Insert customer with authentication fields
	query := `INSERT INTO Customer (name_on_contract, address, unique_id, email, phone_number, 
		password_hash, force_password_change, active, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, TRUE, ?, NOW())`

	result, err := ch.db.Exec(query, req.NameOnContract, req.Address,
		req.UniqueID, req.Email, req.PhoneNumber, string(hashedPassword), active)
	if err != nil {
		if IsUniqueConstraintError(err) {
			WriteErrorResponse(w, http.StatusConflict, "Customer already exists", "unique_id must be unique")
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create customer", err.Error())
		}
		return
	}

	customerID, err := result.LastInsertId()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get customer ID", err.Error())
		return
	}

	// Retrieve the created customer
	var customer models.Customer
	selectQuery := `SELECT customer_id, name_on_contract, address, unique_id, email, phone_number,
		force_password_change, last_login, failed_login_attempts, locked_until, 
		password_changed_at, active, created_at, updated_at 
		FROM Customer WHERE customer_id = ?`

	err = ch.db.Get(&customer, selectQuery, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve created customer", err.Error())
		return
	}

	// Remove password hash from response
	customer.PasswordHash = ""

	response := map[string]interface{}{
		"customer": customer,
		"message":  "Customer created successfully with provided password.",
	}

	WriteJSONResponse(w, http.StatusCreated, response)
}

// UpdateCustomer updates an existing customer
func (ch *CustomerHandler) UpdateCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "Customer ID must be a number")
		return
	}

	var req models.UpdateCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Check if customer exists
	var exists bool
	err = ch.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Customer WHERE customer_id = ?)", customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}

	if req.NameOnContract != nil {
		setParts = append(setParts, "name_on_contract = ?")
		args = append(args, *req.NameOnContract)
	}
	if req.Address != nil {
		setParts = append(setParts, "address = ?")
		args = append(args, *req.Address)
	}
	if req.Email != nil {
		setParts = append(setParts, "email = ?")
		args = append(args, *req.Email)
	}
	if req.PhoneNumber != nil {
		setParts = append(setParts, "phone_number = ?")
		args = append(args, *req.PhoneNumber)
	}
	if req.Active != nil {
		setParts = append(setParts, "active = ?")
		args = append(args, *req.Active)
	}

	if len(setParts) == 0 {
		WriteErrorResponse(w, http.StatusBadRequest, "No fields to update", "")
		return
	}

	// Add updated_at and customer_id to query
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, customerID)

	query := "UPDATE Customer SET " + JoinStrings(setParts, ", ") + " WHERE customer_id = ?"

	_, err = ch.db.Exec(query, args...)
	if err != nil {
		if IsUniqueConstraintError(err) {
			WriteErrorResponse(w, http.StatusConflict, "Unique constraint violation", "unique_id must be unique")
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update customer", err.Error())
		}
		return
	}

	// Retrieve updated customer
	var customer models.Customer
	selectQuery := `SELECT customer_id, name_on_contract, address, unique_id, email, phone_number,
		force_password_change, last_login, failed_login_attempts, locked_until, 
		password_changed_at, active, created_at, updated_at 
		FROM Customer WHERE customer_id = ?`

	err = ch.db.Get(&customer, selectQuery, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve updated customer", err.Error())
		return
	}

	// Remove password hash from response
	customer.PasswordHash = ""

	WriteJSONResponse(w, http.StatusOK, customer)
}

// AdminResetCustomerPassword allows admin or API key to reset a customer's password
func (ch *CustomerHandler) AdminResetCustomerPassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "")
		return
	}

	var req models.AdminResetCustomerPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	authContext := middleware.GetAuthContext(r)
	adminID := -1
	if authContext != nil && authContext.UserID != nil {
		adminID = *authContext.UserID
	}

	authService := services.NewAuthService(ch.db, os.Getenv("JWT_SECRET"))
	if err := authService.AdminResetCustomerPassword(adminID, customerID, req.NewPassword); err != nil {
		if strings.Contains(err.Error(), "customer") {
			WriteErrorResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to reset password", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Customer password reset successfully",
	})
}

// AdminGenerateCustomerPassword generates a random password for a customer (admin only)
func (ch *CustomerHandler) AdminGenerateCustomerPassword(w http.ResponseWriter, r *http.Request) {
	authContext := middleware.GetAuthContext(r)
	if authContext == nil || authContext.UserID == nil {
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "")
		return
	}

	// Use the auth service to generate a new password
	authService := services.NewAuthService(ch.db, os.Getenv("JWT_SECRET"))
	newPassword, err := authService.GenerateRandomPasswordForCustomer(*authContext.UserID, customerID)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient permissions") {
			WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", err.Error())
		} else if strings.Contains(err.Error(), "customer") {
			WriteErrorResponse(w, http.StatusNotFound, "Customer not found", err.Error())
		} else {
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to generate password", err.Error())
		}
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":      "Customer password generated successfully",
		"new_password": newPassword,
	})
}

// DeleteCustomer deletes a customer (checks for contract assignments)
func (ch *CustomerHandler) DeleteCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "Customer ID must be a number")
		return
	}

	// Check if customer exists
	var exists bool
	err = ch.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Customer WHERE customer_id = ?)", customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

	// Check if customer has any contracts assigned
	var contractCount int
	err = ch.db.Get(&contractCount, 
		"SELECT COUNT(*) FROM Contract_Customer_Mapping WHERE customer_id = ?", customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if contractCount > 0 {
		WriteErrorResponse(w, http.StatusConflict, "Cannot delete customer", 
			"Customer is assigned to contracts. Remove contract assignments first.")
		return
	}

	query := `DELETE FROM Customer WHERE customer_id = ?`

	_, err = ch.db.Exec(query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete customer", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Customer deleted successfully",
	})
}

// UnlockCustomer unlocks a locked customer account (admin only)
func (ch *CustomerHandler) UnlockCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "")
		return
	}

	query := `UPDATE Customer
		SET locked_until = NULL, failed_login_attempts = 0, updated_at = NOW()
		WHERE customer_id = ?`

	result, err := ch.db.Exec(query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to unlock customer", err.Error())
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get rows affected", err.Error())
		return
	}

	if rowsAffected == 0 {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "Customer unlocked successfully"})
}

// GetCustomerAuth returns the authentication status for a customer (admin only)
func (ch *CustomerHandler) GetCustomerAuth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	customerID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer ID", "")
		return
	}

	query := `SELECT customer_id, email, force_password_change, last_login, 
		failed_login_attempts, locked_until, password_changed_at, active
		FROM Customer WHERE customer_id = ?`

	var authInfo struct {
		CustomerID          int        `json:"customer_id" db:"customer_id"`
		Email               *string    `json:"email" db:"email"`
		ForcePasswordChange bool       `json:"force_password_change" db:"force_password_change"`
		LastLogin           *time.Time `json:"last_login" db:"last_login"`
		FailedLoginAttempts int        `json:"failed_login_attempts" db:"failed_login_attempts"`
		LockedUntil         *time.Time `json:"locked_until" db:"locked_until"`
		PasswordChangedAt   time.Time  `json:"password_changed_at" db:"password_changed_at"`
		Active              bool       `json:"active" db:"active"`
	}

	err = ch.db.Get(&authInfo, query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

	// Add computed fields
	response := map[string]interface{}{
		"customer_id":            authInfo.CustomerID,
		"email":                  authInfo.Email,
		"force_password_change":  authInfo.ForcePasswordChange,
		"last_login":             authInfo.LastLogin,
		"failed_login_attempts":  authInfo.FailedLoginAttempts,
		"locked_until":           authInfo.LockedUntil,
		"password_changed_at":    authInfo.PasswordChangedAt,
		"active":                 authInfo.Active,
		"is_locked":              authInfo.LockedUntil != nil && authInfo.LockedUntil.After(time.Now()),
		"has_password":           true, // We don't expose whether password exists
		"password_age_days":      int(time.Since(authInfo.PasswordChangedAt).Hours() / 24),
	}

	WriteJSONResponse(w, http.StatusOK, response)
}
