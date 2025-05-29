package handlers

import (
    "net/http"
    "time"
)

// HealthCheckDetailed returns detailed health status
func (h *Handler) HealthCheckDetailed(w http.ResponseWriter, r *http.Request) {
    status := map[string]interface{}{
        "service": "sense-security-api",
        "status": "ok",
        "timestamp": time.Now().Format(time.RFC3339),
    }
    
    // Check database
    dbStart := time.Now()
    if err := h.db.Ping(); err != nil {
        status["status"] = "degraded"
        status["database"] = map[string]interface{}{
            "status": "error",
            "error": err.Error(),
            "latency_ms": time.Since(dbStart).Milliseconds(),
        }
    } else {
        // Try a simple query
        var result int
        err := h.db.QueryRow("SELECT 1").Scan(&result)
        if err != nil {
            status["status"] = "degraded"
            status["database"] = map[string]interface{}{
                "status": "error",
                "error": err.Error(),
                "latency_ms": time.Since(dbStart).Milliseconds(),
            }
        } else {
            status["database"] = map[string]interface{}{
                "status": "healthy",
                "latency_ms": time.Since(dbStart).Milliseconds(),
            }
        }
    }
    
    // Get connection pool stats
    dbStats := h.db.Stats()
    status["connection_pool"] = map[string]interface{}{
        "open_connections": dbStats.OpenConnections,
        "in_use": dbStats.InUse,
        "idle": dbStats.Idle,
        "wait_count": dbStats.WaitCount,
        "wait_duration_ms": dbStats.WaitDuration.Milliseconds(),
        "max_idle_closed": dbStats.MaxIdleClosed,
        "max_lifetime_closed": dbStats.MaxLifetimeClosed,
    }
    
    if status["status"] == "ok" {
        respondJSON(w, http.StatusOK, status)
    } else {
        respondJSON(w, http.StatusServiceUnavailable, status)
    }
}
