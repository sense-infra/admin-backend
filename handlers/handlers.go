package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sense-security/api/db"
)

// Handler holds all the handler dependencies
type Handler struct {
	db *db.DB
}

// New creates a new handler with the given database
func New(database *db.DB) *Handler {
	return &Handler{
		db: database,
	}
}

// HealthCheck returns the health status of the API
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "ok",
		"service": "sense-security-api",
	}
	respondJSON(w, http.StatusOK, response)
}

// ReadinessCheck checks if the API is ready to serve requests
func (h *Handler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	if err := h.db.Ping(); err != nil {
		respondError(w, http.StatusServiceUnavailable, "Database connection failed")
		return
	}
	
	response := map[string]string{
		"status": "ready",
		"database": "connected",
	}
	respondJSON(w, http.StatusOK, response)
}

// Helper functions

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			// Log error but don't write again to avoid multiple writes
			_ = err
		}
	}
}

// respondError writes an error response
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// parseJSON parses the request body into the given interface
func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// getPaginationParams extracts pagination parameters from request
func getPaginationParams(r *http.Request) (limit, offset int) {
	limit = 50 // default
	offset = 0 // default
	
	// Parse from query parameters
	query := r.URL.Query()
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := query.Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	
	return limit, offset
}
