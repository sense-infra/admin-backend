package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/sense-security/api/models"
)

// ContractHandler handles contract-related requests
type ContractHandler struct {
	*BaseHandler
}

func NewContractHandler(database *sqlx.DB) *ContractHandler {
	return &ContractHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// GetContracts returns a list of all contracts
func (ch *ContractHandler) GetContracts(w http.ResponseWriter, r *http.Request) {
	query := `SELECT contract_id, service_address, notification_email, notification_phone, 
		start_date, end_date, created_at, updated_at FROM Contract ORDER BY created_at DESC`
	
	var contracts []models.Contract
	err := ch.db.Select(&contracts, query)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve contracts", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, contracts)
}

// GetContract returns a specific contract by ID
func (ch *ContractHandler) GetContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	query := `SELECT contract_id, service_address, notification_email, notification_phone, 
		start_date, end_date, created_at, updated_at FROM Contract WHERE contract_id = ?`
	
	var contract models.Contract
	err = ch.db.Get(&contract, query, contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, contract)
}

// CreateContract creates a new contract
func (ch *ContractHandler) CreateContract(w http.ResponseWriter, r *http.Request) {
	var req models.CreateContractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate required fields
	if req.ServiceAddress == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required field", "service_address is required")
		return
	}

	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required dates", "start_date and end_date are required")
		return
	}

	if req.EndDate.Before(req.StartDate) {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid date range", "end_date must be after start_date")
		return
	}

	// Insert contract
	query := `INSERT INTO Contract (service_address, notification_email, notification_phone, start_date, end_date) 
		VALUES (?, ?, ?, ?, ?)`
	
	result, err := ch.db.Exec(query, req.ServiceAddress, req.NotificationEmail, 
		req.NotificationPhone, req.StartDate, req.EndDate)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create contract", err.Error())
		return
	}

	contractID, err := result.LastInsertId()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get contract ID", err.Error())
		return
	}

	// Retrieve the created contract
	var contract models.Contract
	query = `SELECT contract_id, service_address, notification_email, notification_phone, 
		start_date, end_date, created_at, updated_at FROM Contract WHERE contract_id = ?`
	
	err = ch.db.Get(&contract, query, contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve created contract", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusCreated, contract)
}

// UpdateContract updates an existing contract
func (ch *ContractHandler) UpdateContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	var req models.UpdateContractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Check if contract exists
	var exists bool
	err = ch.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Contract WHERE contract_id = ?)", contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", "")
		return
	}

	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}
	
	if req.ServiceAddress != nil {
		setParts = append(setParts, "service_address = ?")
		args = append(args, *req.ServiceAddress)
	}
	if req.NotificationEmail != nil {
		setParts = append(setParts, "notification_email = ?")
		args = append(args, *req.NotificationEmail)
	}
	if req.NotificationPhone != nil {
		setParts = append(setParts, "notification_phone = ?")
		args = append(args, *req.NotificationPhone)
	}
	if req.StartDate != nil {
		setParts = append(setParts, "start_date = ?")
		args = append(args, *req.StartDate)
	}
	if req.EndDate != nil {
		setParts = append(setParts, "end_date = ?")
		args = append(args, *req.EndDate)
	}

	if len(setParts) == 0 {
		WriteErrorResponse(w, http.StatusBadRequest, "No fields to update", "")
		return
	}

	// Add updated_at and contract_id to query
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, contractID)

	query := "UPDATE Contract SET " + JoinStrings(setParts, ", ") + " WHERE contract_id = ?"
	
	_, err = ch.db.Exec(query, args...)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update contract", err.Error())
		return
	}

	// Retrieve updated contract
	var contract models.Contract
	selectQuery := `SELECT contract_id, service_address, notification_email, notification_phone, 
		start_date, end_date, created_at, updated_at FROM Contract WHERE contract_id = ?`
	
	err = ch.db.Get(&contract, selectQuery, contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve updated contract", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, contract)
}

// DeleteContract soft deletes a contract (marks as inactive)
func (ch *ContractHandler) DeleteContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	// Check if contract exists
	var exists bool
	err = ch.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Contract WHERE contract_id = ?)", contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", "")
		return
	}

	// For now, we'll actually delete the contract
	query := `DELETE FROM Contract WHERE contract_id = ?`
	
	_, err = ch.db.Exec(query, contractID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete contract", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Contract deleted successfully",
	})
}
