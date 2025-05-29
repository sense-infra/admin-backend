package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/models"
)

// ListContracts returns a list of all contracts
func (h *Handler) ListContracts(w http.ResponseWriter, r *http.Request) {
	limit, offset := getPaginationParams(r)
	
	query := `
		SELECT contract_id, service_address, notification_email, 
		       notification_phone, start_date, end_date, created_at, updated_at
		FROM Contract
		ORDER BY contract_id DESC
		LIMIT ? OFFSET ?
	`
	
	rows, err := h.db.Query(query, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch contracts")
		return
	}
	defer rows.Close()
	
	contracts := []models.Contract{}
	for rows.Next() {
		var c models.Contract
		err := rows.Scan(
			&c.ContractID, &c.ServiceAddress, &c.NotificationEmail,
			&c.NotificationPhone, &c.StartDate, &c.EndDate,
			&c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to scan contract")
			return
		}
		contracts = append(contracts, c)
	}
	
	respondJSON(w, http.StatusOK, contracts)
}

// GetContract returns a single contract by ID
func (h *Handler) GetContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	var c models.Contract
	query := `
		SELECT contract_id, service_address, notification_email, 
		       notification_phone, start_date, end_date, created_at, updated_at
		FROM Contract
		WHERE contract_id = ?
	`
	
	err = h.db.QueryRow(query, id).Scan(
		&c.ContractID, &c.ServiceAddress, &c.NotificationEmail,
		&c.NotificationPhone, &c.StartDate, &c.EndDate,
		&c.CreatedAt, &c.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Contract not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch contract")
		return
	}
	
	respondJSON(w, http.StatusOK, c)
}

// CreateContract creates a new contract
func (h *Handler) CreateContract(w http.ResponseWriter, r *http.Request) {
	var c models.Contract
	if err := parseJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate required fields
	if c.ServiceAddress == "" {
		respondError(w, http.StatusBadRequest, "Service address is required")
		return
	}
	
	// Validate dates
	if c.EndDate.Before(c.StartDate) || c.EndDate.Equal(c.StartDate) {
		respondError(w, http.StatusBadRequest, "End date must be after start date")
		return
	}
	
	query := `
		INSERT INTO Contract (service_address, notification_email, 
		                     notification_phone, start_date, end_date)
		VALUES (?, ?, ?, ?, ?)
	`
	
	result, err := h.db.Exec(query, c.ServiceAddress, c.NotificationEmail,
		c.NotificationPhone, c.StartDate, c.EndDate)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create contract")
		return
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get contract ID")
		return
	}
	
	c.ContractID = int(id)
	respondJSON(w, http.StatusCreated, c)
}

// UpdateContract updates an existing contract
func (h *Handler) UpdateContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	var c models.Contract
	if err := parseJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate required fields
	if c.ServiceAddress == "" {
		respondError(w, http.StatusBadRequest, "Service address is required")
		return
	}
	
	// Validate dates
	if c.EndDate.Before(c.StartDate) || c.EndDate.Equal(c.StartDate) {
		respondError(w, http.StatusBadRequest, "End date must be after start date")
		return
	}
	
	query := `
		UPDATE Contract 
		SET service_address = ?, notification_email = ?, 
		    notification_phone = ?, start_date = ?, end_date = ?
		WHERE contract_id = ?
	`
	
	result, err := h.db.Exec(query, c.ServiceAddress, c.NotificationEmail,
		c.NotificationPhone, c.StartDate, c.EndDate, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update contract")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check update result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Contract not found")
		return
	}
	
	c.ContractID = id
	respondJSON(w, http.StatusOK, c)
}

// DeleteContract deletes a contract
func (h *Handler) DeleteContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	// Begin transaction to handle cascading deletes
	tx, err := h.db.Begin()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to start transaction")
		return
	}
	defer tx.Rollback()
	
	// Delete related mappings first
	deleteQueries := []string{
		"DELETE FROM Contract_Customer_Mapping WHERE contract_id = ?",
		"DELETE FROM Contract_Service_Tier WHERE contract_id = ?",
		"DELETE FROM Contract_NVR_Mapping WHERE contract_id = ?",
		"DELETE FROM Contract_RF_Monitoring WHERE contract_id = ?",
	}
	
	for _, q := range deleteQueries {
		if _, err := tx.Exec(q, id); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to delete contract relations")
			return
		}
	}
	
	// Delete the contract
	result, err := tx.Exec("DELETE FROM Contract WHERE contract_id = ?", id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete contract")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check delete result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Contract not found")
		return
	}
	
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to commit transaction")
		return
	}
	
	respondJSON(w, http.StatusNoContent, nil)
}

// ListContractCustomers lists all customers associated with a contract
func (h *Handler) ListContractCustomers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	query := `
		SELECT c.customer_id, c.name_on_contract, c.address, c.unique_id, 
		       c.email, c.phone_number, c.created_at, c.updated_at
		FROM Customer c
		JOIN Contract_Customer_Mapping ccm ON c.customer_id = ccm.customer_id
		WHERE ccm.contract_id = ?
		ORDER BY c.customer_id
	`
	
	rows, err := h.db.Query(query, contractID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch contract customers")
		return
	}
	defer rows.Close()
	
	customers := []models.Customer{}
	for rows.Next() {
		var c models.Customer
		err := rows.Scan(
			&c.CustomerID, &c.NameOnContract, &c.Address, &c.UniqueID,
			&c.Email, &c.PhoneNumber, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to scan customer")
			return
		}
		customers = append(customers, c)
	}
	
	respondJSON(w, http.StatusOK, customers)
}

// AddCustomerToContract adds a customer to a contract
func (h *Handler) AddCustomerToContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	customerID, err := strconv.Atoi(vars["customerId"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	// Check if mapping already exists
	var exists bool
	checkQuery := `
		SELECT EXISTS(
			SELECT 1 FROM Contract_Customer_Mapping 
			WHERE contract_id = ? AND customer_id = ?
		)
	`
	err = h.db.QueryRow(checkQuery, contractID, customerID).Scan(&exists)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check existing mapping")
		return
	}
	
	if exists {
		respondError(w, http.StatusConflict, "Customer already assigned to contract")
		return
	}
	
	// Create the mapping
	insertQuery := `
		INSERT INTO Contract_Customer_Mapping (contract_id, customer_id)
		VALUES (?, ?)
	`
	
	_, err = h.db.Exec(insertQuery, contractID, customerID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add customer to contract")
		return
	}
	
	respondJSON(w, http.StatusCreated, map[string]string{
		"message": "Customer added to contract successfully",
	})
}

// RemoveCustomerFromContract removes a customer from a contract
func (h *Handler) RemoveCustomerFromContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	customerID, err := strconv.Atoi(vars["customerId"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	query := `
		DELETE FROM Contract_Customer_Mapping 
		WHERE contract_id = ? AND customer_id = ?
	`
	
	result, err := h.db.Exec(query, contractID, customerID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to remove customer from contract")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check delete result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Customer not assigned to this contract")
		return
	}
	
	respondJSON(w, http.StatusNoContent, nil)
}

// AssignServiceTier assigns a service tier to a contract
func (h *Handler) AssignServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	var req struct {
		ServiceTierID int       `json:"service_tier_id"`
		StartDate     time.Time `json:"start_date"`
		EndDate       time.Time `json:"end_date"`
	}
	
	if err := parseJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	// Validate dates
	if req.EndDate.Before(req.StartDate) || req.EndDate.Equal(req.StartDate) {
		respondError(w, http.StatusBadRequest, "End date must be after start date")
		return
	}
	
	// Check for overlapping service tiers
	overlapQuery := `
		SELECT EXISTS(
			SELECT 1 FROM Contract_Service_Tier
			WHERE contract_id = ?
			AND ((start_date <= ? AND end_date >= ?)
			OR (start_date <= ? AND end_date >= ?))
		)
	`
	
	var hasOverlap bool
	err = h.db.QueryRow(overlapQuery, contractID, req.StartDate, req.StartDate, 
		req.EndDate, req.EndDate).Scan(&hasOverlap)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check overlapping tiers")
		return
	}
	
	if hasOverlap {
		respondError(w, http.StatusConflict, "Service tier dates overlap with existing assignment")
		return
	}
	
	// Insert the new service tier assignment
	insertQuery := `
		INSERT INTO Contract_Service_Tier (contract_id, service_tier_id, start_date, end_date)
		VALUES (?, ?, ?, ?)
	`
	
	result, err := h.db.Exec(insertQuery, contractID, req.ServiceTierID, req.StartDate, req.EndDate)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to assign service tier")
		return
	}
	
	id, _ := result.LastInsertId()
	
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"contract_service_tier_id": id,
		"message": "Service tier assigned successfully",
	})
}

// GetCurrentServiceTier gets the current active service tier for a contract
func (h *Handler) GetCurrentServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid contract ID")
		return
	}
	
	query := `
		SELECT st.service_tier_id, st.name, st.description, st.config,
		       cst.start_date, cst.end_date
		FROM Service_Tier st
		JOIN Contract_Service_Tier cst ON st.service_tier_id = cst.service_tier_id
		WHERE cst.contract_id = ?
		AND CURDATE() BETWEEN cst.start_date AND cst.end_date
		ORDER BY cst.start_date DESC
		LIMIT 1
	`
	
	var result struct {
		models.ServiceTier
		StartDate time.Time `json:"start_date"`
		EndDate   time.Time `json:"end_date"`
	}
	
	err = h.db.QueryRow(query, contractID).Scan(
		&result.ServiceTierID, &result.Name, &result.Description,
		&result.Config, &result.StartDate, &result.EndDate,
	)
	
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "No active service tier found for contract")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch service tier")
		return
	}
	
	respondJSON(w, http.StatusOK, result)
}
