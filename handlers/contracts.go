package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

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

// JoinStrings is already defined in common.go - no need to redefine it here

// Enhanced error response helper
func WriteDetailedErrorResponse(w http.ResponseWriter, statusCode int, message, error string, details map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"message": message,
		"error":   error,
	}
	
	if details != nil {
		response["details"] = details
	}
	
	json.NewEncoder(w).Encode(response)
}

// Add validation helper function
func validateContractDates(startDate, endDate models.CustomDate) error {
	if endDate.Before(startDate) || endDate.Equal(startDate) {
		return fmt.Errorf("end_date must be after start_date")
	}
	
	// Check if start date is too far in the past (optional)
	oneYearAgo := models.CustomDate{Time: time.Now().AddDate(-1, 0, 0)}
	if startDate.Before(oneYearAgo) {
		return fmt.Errorf("start_date cannot be more than 1 year in the past")
	}
	
	// Check if end date is too far in the future (optional)
	tenYearsFromNow := models.CustomDate{Time: time.Now().AddDate(10, 0, 0)}
	if endDate.After(tenYearsFromNow) {
		return fmt.Errorf("end_date cannot be more than 10 years in the future")
	}
	
	return nil
}

// GetContracts returns a list of all contracts with customer and service tier info
func (ch *ContractHandler) GetContracts(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT
			c.contract_id,
			c.service_address,
			c.notification_email,
			c.notification_phone,
			c.start_date,
			c.end_date,
			c.created_at,
			c.updated_at,
			cust.customer_id,
			cust.name_on_contract as customer_name,
			st.service_tier_id,
			st.name as service_tier_name
		FROM Contract c
		LEFT JOIN Contract_Customer_Mapping ccm ON c.contract_id = ccm.contract_id
		LEFT JOIN Customer cust ON ccm.customer_id = cust.customer_id
		LEFT JOIN Contract_Service_Tier cst ON c.contract_id = cst.contract_id
			AND cst.start_date <= CURDATE()
			AND cst.end_date >= CURDATE()
		LEFT JOIN Service_Tier st ON cst.service_tier_id = st.service_tier_id
		ORDER BY c.created_at DESC`

	rows, err := ch.db.Query(query)
	if err != nil {
		log.Printf("Failed to query contracts: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve contracts", err.Error())
		return
	}
	defer rows.Close()

	contractsMap := make(map[int]*models.ContractWithDetails)

	for rows.Next() {
		var contract models.ContractWithDetails
		var customerID, serviceTierID *int
		var customerName, serviceTierName *string

		err := rows.Scan(
			&contract.ContractID,
			&contract.ServiceAddress,
			&contract.NotificationEmail,
			&contract.NotificationPhone,
			&contract.StartDate,
			&contract.EndDate,
			&contract.CreatedAt,
			&contract.UpdatedAt,
			&customerID,
			&customerName,
			&serviceTierID,
			&serviceTierName,
		)
		if err != nil {
			log.Printf("Failed to scan contract data: %v", err)
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to scan contract data", err.Error())
			return
		}

		// Check if contract already exists in map
		if existingContract, exists := contractsMap[contract.ContractID]; exists {
			contract = *existingContract
		} else {
			contract.Customers = []models.CustomerBasic{}
			contract.CurrentServiceTier = nil
		}

		// Add customer if present and not already added
		if customerID != nil && customerName != nil {
			customerExists := false
			for _, cust := range contract.Customers {
				if cust.CustomerID == *customerID {
					customerExists = true
					break
				}
			}
			if !customerExists {
				contract.Customers = append(contract.Customers, models.CustomerBasic{
					CustomerID:     *customerID,
					NameOnContract: *customerName,
				})
			}
		}

		// Set service tier if present
		if serviceTierID != nil && serviceTierName != nil {
			contract.CurrentServiceTier = &models.ServiceTierBasic{
				ServiceTierID: *serviceTierID,
				Name:          *serviceTierName,
			}
		}

		contractsMap[contract.ContractID] = &contract
	}

	// Convert map to slice
	contracts := make([]models.ContractWithDetails, 0, len(contractsMap))
	for _, contract := range contractsMap {
		contracts = append(contracts, *contract)
	}

	WriteJSONResponse(w, http.StatusOK, contracts)
}

// GetContract returns a specific contract by ID with full relationship details
func (ch *ContractHandler) GetContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	// Get basic contract info
	query := `SELECT contract_id, service_address, notification_email, notification_phone,
		start_date, end_date, created_at, updated_at FROM Contract WHERE contract_id = ?`

	var contract models.ContractWithDetails
	err = ch.db.Get(&contract, query, contractID)
	if err != nil {
		log.Printf("Failed to get contract %d: %v", contractID, err)
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", "")
		return
	}

	// Get assigned customers
	customerQuery := `
		SELECT c.customer_id, c.name_on_contract, c.email, c.phone_number
		FROM Customer c
		JOIN Contract_Customer_Mapping ccm ON c.customer_id = ccm.customer_id
		WHERE ccm.contract_id = ?`

	err = ch.db.Select(&contract.Customers, customerQuery, contractID)
	if err != nil {
		log.Printf("Failed to get contract customers: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get contract customers", err.Error())
		return
	}

	// Get current service tier
	serviceTierQuery := `
		SELECT st.service_tier_id, st.name, st.description
		FROM Service_Tier st
		JOIN Contract_Service_Tier cst ON st.service_tier_id = cst.service_tier_id
		WHERE cst.contract_id = ?
		AND cst.start_date <= CURDATE()
		AND cst.end_date >= CURDATE()
		LIMIT 1`

	var serviceTier models.ServiceTierBasic
	err = ch.db.Get(&serviceTier, serviceTierQuery, contractID)
	if err == nil {
		contract.CurrentServiceTier = &serviceTier
	}

	WriteJSONResponse(w, http.StatusOK, contract)
}

// CreateContract creates a new contract with customer and service tier assignment
func (ch *ContractHandler) CreateContract(w http.ResponseWriter, r *http.Request) {
	// Test database connection first
	if err := ch.db.Ping(); err != nil {
		WriteErrorResponse(w, http.StatusServiceUnavailable, "Database connection failed", err.Error())
		return
	}

	var req models.CreateContractWithRelationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode create contract request: %v", err)
		WriteDetailedErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error(), nil)
		return
	}

	log.Printf("Creating contract with request: %+v", req)

	// Enhanced validation with detailed error messages
	details := make(map[string]string)

	if req.ServiceAddress == "" {
		details["service_address"] = "Service address is required"
	}
	if req.StartDate.IsZero() {
		details["start_date"] = "Start date is required"
	}
	if req.EndDate.IsZero() {
		details["end_date"] = "End date is required"
	}
	if req.CustomerID == 0 {
		details["customer_id"] = "Customer ID is required"
	}
	if req.ServiceTierID == 0 {
		details["service_tier_id"] = "Service tier ID is required"
	}

	// Date validation
	if !req.StartDate.IsZero() && !req.EndDate.IsZero() {
		if err := validateContractDates(req.StartDate, req.EndDate); err != nil {
			details["dates"] = err.Error()
		}
	}

	if len(details) > 0 {
		WriteDetailedErrorResponse(w, http.StatusBadRequest, "Validation failed", "Missing or invalid required fields", details)
		return
	}

	// Verify customer exists
	var customerExists bool
	err := ch.db.Get(&customerExists, "SELECT EXISTS(SELECT 1 FROM Customer WHERE customer_id = ?)", req.CustomerID)
	if err != nil {
		log.Printf("Failed to check customer existence: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !customerExists {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer", "Customer does not exist")
		return
	}

	// Verify service tier exists
	var serviceTierExists bool
	err = ch.db.Get(&serviceTierExists, "SELECT EXISTS(SELECT 1 FROM Service_Tier WHERE service_tier_id = ?)", req.ServiceTierID)
	if err != nil {
		log.Printf("Failed to check service tier existence: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !serviceTierExists {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid service tier", "Service tier does not exist")
		return
	}

	// Start transaction
	tx, err := ch.db.Beginx()
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to start transaction", err.Error())
		return
	}
	defer tx.Rollback()

	// Insert contract - use the String() method to get YYYY-MM-DD format
	contractQuery := `INSERT INTO Contract (service_address, notification_email, notification_phone, start_date, end_date, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, NOW(), NOW())`
	
	result, err := tx.Exec(contractQuery, 
		req.ServiceAddress, 
		req.NotificationEmail,
		req.NotificationPhone, 
		req.StartDate.String(),  // Use String() method for YYYY-MM-DD format
		req.EndDate.String())    // Use String() method for YYYY-MM-DD format
	if err != nil {
		log.Printf("Failed to insert contract: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create contract", err.Error())
		return
	}

	contractID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get contract ID: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get contract ID", err.Error())
		return
	}

	log.Printf("Created contract with ID: %d", contractID)

	// Insert contract-customer mapping
	customerMappingQuery := `INSERT INTO Contract_Customer_Mapping (contract_id, customer_id, created_at, updated_at) VALUES (?, ?, NOW(), NOW())`
	_, err = tx.Exec(customerMappingQuery, contractID, req.CustomerID)
	if err != nil {
		log.Printf("Failed to create customer mapping: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to assign customer to contract", err.Error())
		return
	}

	// Insert contract-service tier mapping
	serviceTierMappingQuery := `INSERT INTO Contract_Service_Tier (contract_id, service_tier_id, start_date, end_date, created_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())`
	_, err = tx.Exec(serviceTierMappingQuery, contractID, req.ServiceTierID, 
		req.StartDate.String(), req.EndDate.String())  // Use String() method
	if err != nil {
		log.Printf("Failed to create service tier mapping: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to assign service tier to contract", err.Error())
		return
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to commit transaction", err.Error())
		return
	}

	log.Printf("Successfully created contract %d", contractID)

	// Retrieve the created contract with relationships
	vars := map[string]string{"id": strconv.FormatInt(contractID, 10)}
	req_copy := mux.SetURLVars(r, vars)
	ch.GetContract(w, req_copy)
}

// UpdateContract updates an existing contract and its relationships
func (ch *ContractHandler) UpdateContract(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	contractID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid contract ID", "Contract ID must be a number")
		return
	}

	// Test database connection
	if err := ch.db.Ping(); err != nil {
		WriteErrorResponse(w, http.StatusServiceUnavailable, "Database connection failed", err.Error())
		return
	}

	var req models.UpdateContractWithRelationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode update contract request: %v", err)
		WriteDetailedErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error(), nil)
		return
	}

	log.Printf("Updating contract %d with request: %+v", contractID, req)

	// Check if contract exists
	var exists bool
	err = ch.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Contract WHERE contract_id = ?)", contractID)
	if err != nil {
		log.Printf("Failed to check contract existence: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", "")
		return
	}

	// Date validation if dates are provided
	if req.StartDate != nil && req.EndDate != nil {
		if err := validateContractDates(*req.StartDate, *req.EndDate); err != nil {
			WriteErrorResponse(w, http.StatusBadRequest, "Invalid date range", err.Error())
			return
		}
	}

	// Start transaction
	tx, err := ch.db.Beginx()
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to start transaction", err.Error())
		return
	}
	defer tx.Rollback()

	// Build dynamic update query for contract
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
		args = append(args, req.StartDate.String())  // Use String() method
	}
	if req.EndDate != nil {
		setParts = append(setParts, "end_date = ?")
		args = append(args, req.EndDate.String())    // Use String() method
	}

	// Update contract if there are fields to update
	if len(setParts) > 0 {
		setParts = append(setParts, "updated_at = NOW()")
		args = append(args, contractID)
		query := "UPDATE Contract SET " + JoinStrings(setParts, ", ") + " WHERE contract_id = ?"
		_, err = tx.Exec(query, args...)
		if err != nil {
			log.Printf("Failed to update contract: %v", err)
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update contract", err.Error())
			return
		}
	}

	// Update customer assignment if provided
	if req.CustomerID != nil {
		// Verify customer exists
		var customerExists bool
		err := tx.Get(&customerExists, "SELECT EXISTS(SELECT 1 FROM Customer WHERE customer_id = ?)", *req.CustomerID)
		if err != nil || !customerExists {
			WriteErrorResponse(w, http.StatusBadRequest, "Invalid customer", "Customer does not exist")
			return
		}

		// Delete existing customer mapping
		_, err = tx.Exec("DELETE FROM Contract_Customer_Mapping WHERE contract_id = ?", contractID)
		if err != nil {
			log.Printf("Failed to delete existing customer mapping: %v", err)
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update customer assignment", err.Error())
			return
		}

		// Insert new customer mapping
		_, err = tx.Exec("INSERT INTO Contract_Customer_Mapping (contract_id, customer_id, created_at, updated_at) VALUES (?, ?, NOW(), NOW())", contractID, *req.CustomerID)
		if err != nil {
			log.Printf("Failed to create new customer mapping: %v", err)
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to assign new customer", err.Error())
			return
		}
	}

	// Update service tier assignment if provided
	if req.ServiceTierID != nil {
		// Verify service tier exists
		var serviceTierExists bool
		err := tx.Get(&serviceTierExists, "SELECT EXISTS(SELECT 1 FROM Service_Tier WHERE service_tier_id = ?)", *req.ServiceTierID)
		if err != nil || !serviceTierExists {
			WriteErrorResponse(w, http.StatusBadRequest, "Invalid service tier", "Service tier does not exist")
			return
		}

		// Get contract dates for service tier assignment
		var startDate, endDate string
		if req.StartDate != nil {
			startDate = req.StartDate.String()
		} else {
			err = tx.Get(&startDate, "SELECT start_date FROM Contract WHERE contract_id = ?", contractID)
			if err != nil {
				log.Printf("Failed to get contract start date: %v", err)
				WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get contract start date", err.Error())
				return
			}
		}
		
		if req.EndDate != nil {
			endDate = req.EndDate.String()
		} else {
			err = tx.Get(&endDate, "SELECT end_date FROM Contract WHERE contract_id = ?", contractID)
			if err != nil {
				log.Printf("Failed to get contract end date: %v", err)
				WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get contract end date", err.Error())
				return
			}
		}

		// Delete existing service tier mapping
		_, err = tx.Exec("DELETE FROM Contract_Service_Tier WHERE contract_id = ?", contractID)
		if err != nil {
			log.Printf("Failed to delete existing service tier mapping: %v", err)
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update service tier assignment", err.Error())
			return
		}

		// Insert new service tier mapping
		_, err = tx.Exec("INSERT INTO Contract_Service_Tier (contract_id, service_tier_id, start_date, end_date, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
			contractID, *req.ServiceTierID, startDate, endDate)
		if err != nil {
			log.Printf("Failed to create new service tier mapping: %v", err)
			WriteErrorResponse(w, http.StatusInternalServerError, "Failed to assign new service tier", err.Error())
			return
		}
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit update transaction: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to commit transaction", err.Error())
		return
	}

	log.Printf("Successfully updated contract %d", contractID)

	// Retrieve updated contract with relationships
	vars_copy := map[string]string{"id": strconv.Itoa(contractID)}
	req_copy := mux.SetURLVars(r, vars_copy)
	ch.GetContract(w, req_copy)
}

// DeleteContract deletes a contract and all its relationships
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
		log.Printf("Failed to check contract existence: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Contract not found", "")
		return
	}

	// Start transaction
	tx, err := ch.db.Beginx()
	if err != nil {
		log.Printf("Failed to start delete transaction: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to start transaction", err.Error())
		return
	}
	defer tx.Rollback()

	// Delete all related mappings first (foreign key constraints)
	_, err = tx.Exec("DELETE FROM Contract_Customer_Mapping WHERE contract_id = ?", contractID)
	if err != nil {
		log.Printf("Failed to delete customer mappings: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete customer mappings", err.Error())
		return
	}

	_, err = tx.Exec("DELETE FROM Contract_Service_Tier WHERE contract_id = ?", contractID)
	if err != nil {
		log.Printf("Failed to delete service tier mappings: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete service tier mappings", err.Error())
		return
	}

	// Delete the contract
	_, err = tx.Exec("DELETE FROM Contract WHERE contract_id = ?", contractID)
	if err != nil {
		log.Printf("Failed to delete contract: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete contract", err.Error())
		return
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		log.Printf("Failed to commit delete transaction: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to commit transaction", err.Error())
		return
	}

	log.Printf("Successfully deleted contract %d", contractID)

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Contract and all related assignments deleted successfully",
	})
}
