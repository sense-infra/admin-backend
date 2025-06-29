package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/sense-security/api/models"
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
		created_at, updated_at FROM Customer ORDER BY created_at DESC`

	var customers []models.Customer
	err := ch.db.Select(&customers, query)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve customers", err.Error())
		return
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
		created_at, updated_at FROM Customer WHERE customer_id = ?`

	var customer models.Customer
	err = ch.db.Get(&customer, query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Customer not found", "")
		return
	}

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

	// Insert customer
	query := `INSERT INTO Customer (name_on_contract, address, unique_id, email, phone_number)
		VALUES (?, ?, ?, ?, ?)`

	result, err := ch.db.Exec(query, req.NameOnContract, req.Address,
		req.UniqueID, req.Email, req.PhoneNumber)
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
	query = `SELECT customer_id, name_on_contract, address, unique_id, email, phone_number,
		created_at, updated_at FROM Customer WHERE customer_id = ?`

	err = ch.db.Get(&customer, query, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve created customer", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusCreated, customer)
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
		created_at, updated_at FROM Customer WHERE customer_id = ?`

	err = ch.db.Get(&customer, selectQuery, customerID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve updated customer", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, customer)
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
