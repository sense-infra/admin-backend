package handlers

import (
	"net/http"
	"runtime"
	"time"

	"github.com/jmoiron/sqlx"
)

// DiagnosticsHandler handles diagnostic requests
type DiagnosticsHandler struct {
	*BaseHandler
}

func NewDiagnosticsHandler(database *sqlx.DB) *DiagnosticsHandler {
	return &DiagnosticsHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// GetDatabaseStatus returns the current database connection status
func (dh *DiagnosticsHandler) GetDatabaseStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"database":  "MariaDB",
	}

	// Test database connection
	if err := dh.db.Ping(); err != nil {
		status["status"] = "disconnected"
		status["error"] = err.Error()
		WriteErrorResponse(w, http.StatusServiceUnavailable, "Database unavailable", err.Error())
		return
	}

	// Get database stats
	stats := dh.db.Stats()
	status["status"] = "connected"
	status["stats"] = map[string]interface{}{
		"open_connections":     stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration":       stats.WaitDuration.String(),
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
	}

	// Test a simple query
	var result int
	err := dh.db.Get(&result, "SELECT 1")
	if err != nil {
		status["query_test"] = "failed"
		status["query_error"] = err.Error()
	} else {
		status["query_test"] = "success"
	}

	WriteJSONResponse(w, http.StatusOK, status)
}

// GetSystemInfo returns system information
func (dh *DiagnosticsHandler) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"system": map[string]interface{}{
			"go_version":      runtime.Version(),
			"num_goroutines":  runtime.NumGoroutine(),
			"num_cpu":         runtime.NumCPU(),
			"os":              runtime.GOOS,
			"arch":            runtime.GOARCH,
		},
		"memory": map[string]interface{}{
			"alloc":         memStats.Alloc,
			"total_alloc":   memStats.TotalAlloc,
			"sys":           memStats.Sys,
			"num_gc":        memStats.NumGC,
			"gc_cpu_percent": memStats.GCCPUFraction,
		},
		"database": map[string]interface{}{
			"driver": "mysql",
			"stats":  dh.db.Stats(),
		},
	}

	WriteJSONResponse(w, http.StatusOK, info)
}
