package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/sense-security/api/models"
)

// ServiceTierHandler handles service tier-related requests
type ServiceTierHandler struct {
	*BaseHandler
}

func NewServiceTierHandler(database *sqlx.DB) *ServiceTierHandler {
	return &ServiceTierHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// GetServiceTiers returns a list of all service tiers
func (sth *ServiceTierHandler) GetServiceTiers(w http.ResponseWriter, r *http.Request) {
	query := `SELECT service_tier_id, name, description, config, created_at, updated_at 
		FROM Service_Tier ORDER BY name ASC`
	
	var serviceTiers []models.ServiceTier
	err := sth.db.Select(&serviceTiers, query)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve service tiers", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, serviceTiers)
}

// GetServiceTier returns a specific service tier by ID
func (sth *ServiceTierHandler) GetServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceTierID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid service tier ID", "Service tier ID must be a number")
		return
	}

	query := `SELECT service_tier_id, name, description, config, created_at, updated_at 
		FROM Service_Tier WHERE service_tier_id = ?`
	
	var serviceTier models.ServiceTier
	err = sth.db.Get(&serviceTier, query, serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, "Service tier not found", "")
		return
	}

	WriteJSONResponse(w, http.StatusOK, serviceTier)
}

// CreateServiceTier creates a new service tier
func (sth *ServiceTierHandler) CreateServiceTier(w http.ResponseWriter, r *http.Request) {
	var req models.CreateServiceTierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate required fields
	if req.Name == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Missing required field", "name is required")
		return
	}

	// Insert service tier
	query := `INSERT INTO Service_Tier (name, description, config) VALUES (?, ?, ?)`
	
	result, err := sth.db.Exec(query, req.Name, req.Description, req.Config)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to create service tier", err.Error())
		return
	}

	serviceTierID, err := result.LastInsertId()
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get service tier ID", err.Error())
		return
	}

	// Retrieve the created service tier
	var serviceTier models.ServiceTier
	query = `SELECT service_tier_id, name, description, config, created_at, updated_at 
		FROM Service_Tier WHERE service_tier_id = ?`
	
	err = sth.db.Get(&serviceTier, query, serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve created service tier", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusCreated, serviceTier)
}

// UpdateServiceTier updates an existing service tier
func (sth *ServiceTierHandler) UpdateServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceTierID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid service tier ID", "Service tier ID must be a number")
		return
	}

	var req models.UpdateServiceTierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Check if service tier exists
	var exists bool
	err = sth.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Service_Tier WHERE service_tier_id = ?)", serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Service tier not found", "")
		return
	}

	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}
	
	if req.Name != nil {
		setParts = append(setParts, "name = ?")
		args = append(args, *req.Name)
	}
	if req.Description != nil {
		setParts = append(setParts, "description = ?")
		args = append(args, *req.Description)
	}
	if req.Config != nil {
		setParts = append(setParts, "config = ?")
		args = append(args, *req.Config)
	}

	if len(setParts) == 0 {
		WriteErrorResponse(w, http.StatusBadRequest, "No fields to update", "")
		return
	}

	// Add updated_at and service_tier_id to query
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, serviceTierID)

	query := "UPDATE Service_Tier SET " + JoinStrings(setParts, ", ") + " WHERE service_tier_id = ?"
	
	_, err = sth.db.Exec(query, args...)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to update service tier", err.Error())
		return
	}

	// Retrieve updated service tier
	var serviceTier models.ServiceTier
	selectQuery := `SELECT service_tier_id, name, description, config, created_at, updated_at 
		FROM Service_Tier WHERE service_tier_id = ?`
	
	err = sth.db.Get(&serviceTier, selectQuery, serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve updated service tier", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, serviceTier)
}

// DeleteServiceTier deletes a service tier
func (sth *ServiceTierHandler) DeleteServiceTier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceTierID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid service tier ID", "Service tier ID must be a number")
		return
	}

	// Check if service tier exists
	var exists bool
	err = sth.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Service_Tier WHERE service_tier_id = ?)", serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if !exists {
		WriteErrorResponse(w, http.StatusNotFound, "Service tier not found", "")
		return
	}

	// Check if service tier is being used by any contracts
	var contractCount int
	err = sth.db.Get(&contractCount, 
		"SELECT COUNT(*) FROM Contract_Service_Tier WHERE service_tier_id = ?", serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if contractCount > 0 {
		WriteErrorResponse(w, http.StatusConflict, "Cannot delete service tier", 
			"Service tier is currently assigned to contracts")
		return
	}

	// Delete the service tier
	query := `DELETE FROM Service_Tier WHERE service_tier_id = ?`
	
	_, err = sth.db.Exec(query, serviceTierID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete service tier", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Service tier deleted successfully",
	})
}
