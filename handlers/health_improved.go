package handlers

import (
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
)

// ImprovedHealthHandler provides enhanced health checking
type ImprovedHealthHandler struct {
	*BaseHandler
}

func NewImprovedHealthHandler(database *sqlx.DB) *ImprovedHealthHandler {
	return &ImprovedHealthHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// GetDetailedHealth returns detailed health information
func (h *ImprovedHealthHandler) GetDetailedHealth(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	health := map[string]interface{}{
		"service":   "SenseGuard Security Platform",
		"version":   "1.0.0",
		"timestamp": startTime.Unix(),
		"uptime":    time.Since(startTime).String(),
	}

	// Database health check
	if err := h.db.Ping(); err != nil {
		health["status"] = "unhealthy"
		health["database"] = map[string]interface{}{
			"status": "disconnected",
			"error":  err.Error(),
		}
		WriteErrorResponse(w, http.StatusServiceUnavailable, "Service unhealthy", "Database connection failed")
		return
	}

	// Database query test
	var result int
	queryStart := time.Now()
	err := h.db.Get(&result, "SELECT 1")
	queryDuration := time.Since(queryStart)
	
	if err != nil {
		health["status"] = "degraded"
		health["database"] = map[string]interface{}{
			"status":        "connected",
			"query_test":    "failed",
			"query_error":   err.Error(),
			"response_time": queryDuration.Milliseconds(),
		}
	} else {
		health["status"] = "healthy"
		health["database"] = map[string]interface{}{
			"status":        "healthy",
			"query_test":    "passed",
			"response_time": queryDuration.Milliseconds(),
		}
	}

	// Add system info
	health["checks"] = map[string]interface{}{
		"database": health["database"],
	}

	WriteJSONResponse(w, http.StatusOK, health)
}
