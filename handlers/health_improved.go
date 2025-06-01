package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
)

// ImprovedHealthHandler provides enhanced health checking with caching and security
// This is a drop-in replacement that uses the same function names as the original
type ImprovedHealthHandler struct {
	*BaseHandler
	healthCache    map[string]interface{}
	lastCheck      time.Time
	cacheDuration  time.Duration
	mutex          sync.RWMutex
}

func NewImprovedHealthHandler(database *sqlx.DB) *ImprovedHealthHandler {
	return &ImprovedHealthHandler{
		BaseHandler:   NewBaseHandler(database),
		cacheDuration: 30 * time.Second, // Cache for 30 seconds to prevent DB DDoS
		healthCache:   make(map[string]interface{}),
	}
}

// GetDetailedHealth provides enhanced health information with caching protection
// This is the ORIGINAL function name - no main.go changes needed
func (h *ImprovedHealthHandler) GetDetailedHealth(w http.ResponseWriter, r *http.Request) {
	// Check if this is a request for quick health (no DB queries)
	// Look for ?quick=true parameter for load balancer health checks
	if r.URL.Query().Get("quick") == "true" {
		h.getQuickHealth(w, r)
		return
	}

	// Check if this is a request for detailed admin health
	// Look for ?detailed=true parameter for full admin health checks
	if r.URL.Query().Get("detailed") == "true" {
		h.getFullDetailedHealth(w, r)
		return
	}

	// Default behavior: cached health check (protects against DDoS)
	h.getCachedHealth(w, r)
}

// getCachedHealth provides cached basic health status to prevent DB DDoS
func (h *ImprovedHealthHandler) getCachedHealth(w http.ResponseWriter, r *http.Request) {
	h.mutex.RLock()
	
	// Check if cache is still valid
	if time.Since(h.lastCheck) < h.cacheDuration && h.healthCache != nil {
		// Return cached response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Health-Cache", "hit")
		w.Header().Set("X-Health-Type", "cached")
		
		statusCode := http.StatusOK
		if status, ok := h.healthCache["status"]; ok && status == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		}
		
		WriteJSONResponse(w, statusCode, h.healthCache)
		h.mutex.RUnlock()
		return
	}
	
	h.mutex.RUnlock()
	
	// Cache expired, need to refresh (with write lock)
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	// Double-check in case another goroutine updated while waiting for lock
	if time.Since(h.lastCheck) < h.cacheDuration && h.healthCache != nil {
		statusCode := http.StatusOK
		if status, ok := h.healthCache["status"]; ok && status == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Health-Cache", "hit")
		w.Header().Set("X-Health-Type", "cached")
		
		WriteJSONResponse(w, statusCode, h.healthCache)
		return
	}
	
	// Perform actual health check with timeout protection
	health := map[string]interface{}{
		"status":     "healthy",
		"timestamp":  time.Now().Unix(),
		"service":    "SenseGuard Security Platform",
		"version":    "1.0.0",
		"type":       "cached",
		"cache_ttl":  int(h.cacheDuration.Seconds()),
	}

	// Test database connection with timeout to prevent hanging
	done := make(chan error, 1)
	go func() {
		done <- h.db.Ping()
	}()

	select {
	case err := <-done:
		if err != nil {
			health["status"] = "unhealthy"
			health["database"] = "disconnected"
			health["error"] = err.Error()
		} else {
			health["database"] = "connected"
		}
	case <-time.After(5 * time.Second): // 5 second timeout
		health["status"] = "unhealthy"
		health["database"] = "timeout"
		health["error"] = "Database ping timeout after 5 seconds"
	}
	
	// Update cache
	h.healthCache = health
	h.lastCheck = time.Now()
	
	// Send response
	statusCode := http.StatusOK
	if health["status"] == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Health-Cache", "miss")
	w.Header().Set("X-Health-Type", "cached")
	
	WriteJSONResponse(w, statusCode, health)
}

// getQuickHealth provides instant health status without any DB queries
func (h *ImprovedHealthHandler) getQuickHealth(w http.ResponseWriter, r *http.Request) {
	// This endpoint never queries the database - purely for load balancer health checks
	health := map[string]interface{}{
		"status":    "healthy",
		"service":   "SenseGuard Security Platform", 
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"type":      "quick",
		"database":  "not_checked",
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Health-Type", "quick")
	WriteJSONResponse(w, http.StatusOK, health)
}

// getFullDetailedHealth provides comprehensive health information (original detailed behavior)
func (h *ImprovedHealthHandler) getFullDetailedHealth(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	health := map[string]interface{}{
		"service":   "SenseGuard Security Platform",
		"version":   "1.0.0",
		"timestamp": startTime.Unix(),
		"uptime":    time.Since(startTime).String(),
		"type":      "detailed",
	}

	// Database health check with timeout
	dbHealth := make(chan map[string]interface{}, 1)
	go func() {
		dbResult := map[string]interface{}{}
		
		// Test basic connection
		if err := h.db.Ping(); err != nil {
			dbResult["status"] = "disconnected"
			dbResult["error"] = err.Error()
			dbHealth <- dbResult
			return
		}

		// Test actual query execution (original behavior)
		var result int
		queryStart := time.Now()
		err := h.db.Get(&result, "SELECT 1")
		queryDuration := time.Since(queryStart)
		
		if err != nil {
			dbResult["status"] = "connected"
			dbResult["query_test"] = "failed"
			dbResult["query_error"] = err.Error()
			dbResult["response_time"] = queryDuration.Milliseconds()
		} else {
			dbResult["status"] = "healthy"
			dbResult["query_test"] = "passed"
			dbResult["response_time"] = queryDuration.Milliseconds()
		}
		
		dbHealth <- dbResult
	}()

	// Wait for DB check with timeout
	var dbResult map[string]interface{}
	select {
	case dbResult = <-dbHealth:
		// DB check completed normally
	case <-time.After(10 * time.Second):
		// DB check timed out
		dbResult = map[string]interface{}{
			"status": "timeout",
			"error":  "Database health check timeout after 10 seconds",
		}
	}

	// Set overall health status
	if dbResult["status"] == "healthy" {
		health["status"] = "healthy"
	} else if dbResult["status"] == "connected" {
		health["status"] = "degraded" 
	} else {
		health["status"] = "unhealthy"
	}

	// Add database details
	health["database"] = dbResult

	// Add system checks (original behavior)
	health["checks"] = map[string]interface{}{
		"database": dbResult,
	}

	// Determine HTTP status code
	statusCode := http.StatusOK
	if health["status"] == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("X-Health-Type", "detailed")
	WriteJSONResponse(w, statusCode, health)
}
