package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	*BaseHandler
}

func NewHealthHandler(database *sqlx.DB) *HealthHandler {
	return &HealthHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// GetHealth returns the health status of the API
func (h *HealthHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   "SenseGuard API",
		"version":   "1.0.0",
	}

	// Test database connection
	if err := h.db.Ping(); err != nil {
		health["status"] = "unhealthy"
		health["database"] = "disconnected"
		health["error"] = err.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		health["database"] = "connected"
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}
