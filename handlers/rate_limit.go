package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/sense-security/api/middleware"
)

type RateLimitHandler struct {
	db *sqlx.DB
}

func NewRateLimitHandler(db *sqlx.DB) *RateLimitHandler {
	return &RateLimitHandler{db: db}
}

// RateLimitStatus represents the rate limiting status for an API key
type RateLimitStatus struct {
	APIKeyID          int     `json:"api_key_id" db:"api_key_id"`
	KeyName           string  `json:"key_name" db:"key_name"`
	KeyPrefix         string  `json:"key_prefix" db:"key_prefix"`
	RateLimitPerHour  int     `json:"rate_limit_per_hour" db:"rate_limit_per_hour"`
	Active            bool    `json:"active" db:"active"`
	UsageLastHour     int     `json:"usage_last_hour" db:"usage_last_hour"`
	RemainingRequests int     `json:"remaining_requests" db:"remaining_requests"`
	Status            string  `json:"status" db:"status"`
	LastRequestTime   *string `json:"last_request_time" db:"last_request_time"`
	LastUsed          *string `json:"last_used" db:"last_used"`
	TotalUsageCount   int64   `json:"total_usage_count" db:"total_usage_count"`
	CreatedByUsername *string `json:"created_by_username" db:"created_by_username"`
}

// APIKeyRateLimitSummary provides a summary of rate limiting across all keys
type APIKeyRateLimitSummary struct {
	TotalAPIKeys       int `json:"total_api_keys"`
	ActiveAPIKeys      int `json:"active_api_keys"`
	RateLimitedKeys    int `json:"rate_limited_keys"`
	ApproachingLimitKeys int `json:"approaching_limit_keys"`
	TotalRequestsLastHour int64 `json:"total_requests_last_hour"`
}

// GetAllAPIKeyRateLimitStatus returns rate limiting status for all API keys
func (h *RateLimitHandler) GetAllAPIKeyRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	// Check if user has permission to view API key information
	if !middleware.HasPermission(r, "api_keys", "read") {
		writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", 
			"Required permission: api_keys:read")
		return
	}

	// Call the stored procedure to get rate limit status
	query := `CALL GetAllAPIKeyRateLimitStatus()`
	
	rows, err := h.db.Query(query)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	defer rows.Close()

	var statuses []RateLimitStatus
	for rows.Next() {
		var status RateLimitStatus
		err := rows.Scan(
			&status.APIKeyID, &status.KeyName, &status.KeyPrefix,
			&status.RateLimitPerHour, &status.Active, &status.UsageLastHour,
			&status.RemainingRequests, &status.Status, &status.LastRequestTime,
			&status.LastUsed, &status.TotalUsageCount, &status.CreatedByUsername,
		)
		if err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, "Error scanning data", err.Error())
			return
		}
		statuses = append(statuses, status)
	}

	response := map[string]interface{}{
		"api_key_rate_limits": statuses,
		"summary":            h.calculateRateLimitSummary(statuses),
		"timestamp":          getCurrentTimestamp(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetAPIKeyRateLimitStatus returns rate limiting status for a specific API key
func (h *RateLimitHandler) GetAPIKeyRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	// Check permissions
	if !middleware.HasPermission(r, "api_keys", "read") {
		writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", 
			"Required permission: api_keys:read")
		return
	}

	// Get API key ID from URL
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	// Get rate limit status from the view
	query := `
		SELECT 
			api_key_id, key_name, key_prefix, rate_limit_per_hour, active,
			usage_last_hour, remaining_requests, is_rate_limited, 
			approaching_limit, last_request_time
		FROM API_Key_Usage_Last_Hour 
		WHERE api_key_id = ?`
	
	var status struct {
		APIKeyID          int     `db:"api_key_id"`
		KeyName           string  `db:"key_name"`
		KeyPrefix         string  `db:"key_prefix"`
		RateLimitPerHour  int     `db:"rate_limit_per_hour"`
		Active            bool    `db:"active"`
		UsageLastHour     int     `db:"usage_last_hour"`
		RemainingRequests int     `db:"remaining_requests"`
		IsRateLimited     bool    `db:"is_rate_limited"`
		ApproachingLimit  bool    `db:"approaching_limit"`
		LastRequestTime   *string `db:"last_request_time"`
	}

	err = h.db.Get(&status, query, apiKeyID)
	if err != nil {
		writeErrorResponse(w, http.StatusNotFound, "API key not found", err.Error())
		return
	}

	// Determine status string
	statusStr := "LOW_USAGE"
	if status.IsRateLimited {
		statusStr = "RATE_LIMITED"
	} else if status.ApproachingLimit {
		statusStr = "APPROACHING_LIMIT"
	} else if status.UsageLastHour > status.RateLimitPerHour/2 {
		statusStr = "MODERATE_USAGE"
	}

	// Get additional usage statistics
	usageStats, err := h.getDetailedUsageStats(apiKeyID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Error getting usage stats", err.Error())
		return
	}

	response := map[string]interface{}{
		"api_key_id":          status.APIKeyID,
		"key_name":           status.KeyName,
		"key_prefix":         status.KeyPrefix,
		"rate_limit_per_hour": status.RateLimitPerHour,
		"active":             status.Active,
		"usage_last_hour":    status.UsageLastHour,
		"remaining_requests": status.RemainingRequests,
		"status":             statusStr,
		"is_rate_limited":    status.IsRateLimited,
		"approaching_limit":  status.ApproachingLimit,
		"last_request_time":  status.LastRequestTime,
		"utilization_percent": float64(status.UsageLastHour) / float64(status.RateLimitPerHour) * 100,
		"usage_statistics":   usageStats,
		"timestamp":          getCurrentTimestamp(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ResetAPIKeyRateLimit manually resets the rate limit for an API key (admin only)
func (h *RateLimitHandler) ResetAPIKeyRateLimit(w http.ResponseWriter, r *http.Request) {
	// Check admin permissions
	if !middleware.IsAdmin(r) {
		writeErrorResponse(w, http.StatusForbidden, "Admin access required", 
			"Only administrators can reset rate limits")
		return
	}

	// Get API key ID from URL
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	// Delete usage logs for the last hour (effectively resetting the rate limit)
	query := `
		DELETE FROM API_Key_Usage_Log 
		WHERE api_key_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)`
	
	result, err := h.db.Exec(query, apiKeyID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Error resetting rate limit", err.Error())
		return
	}

	rowsAffected, _ := result.RowsAffected()

	// Log the admin action
	userID := middleware.GetUserID(r)
	if userID != nil {
		logQuery := `
			INSERT INTO System_Log (log_level, component, message, metadata) 
			VALUES ('WARNING', 'RATE_LIMITING', 'Admin reset API key rate limit', 
				JSON_OBJECT('api_key_id', ?, 'admin_user_id', ?, 'rows_deleted', ?))`
		h.db.Exec(logQuery, apiKeyID, *userID, rowsAffected)
	}

	response := map[string]interface{}{
		"message":         "Rate limit reset successfully",
		"api_key_id":      apiKeyID,
		"records_removed": rowsAffected,
		"timestamp":       getCurrentTimestamp(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetRateLimitingMetrics returns overall rate limiting metrics for the admin dashboard
func (h *RateLimitHandler) GetRateLimitingMetrics(w http.ResponseWriter, r *http.Request) {
	// Check permissions
	if !middleware.HasPermission(r, "api_keys", "read") {
		writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", 
			"Required permission: api_keys:read")
		return
	}

	// Get overall metrics
	metricsQuery := `
		SELECT 
			COUNT(*) as total_api_keys,
			COUNT(CASE WHEN active = TRUE THEN 1 END) as active_api_keys,
			COUNT(CASE WHEN active = TRUE AND usage_last_hour >= rate_limit_per_hour THEN 1 END) as rate_limited_keys,
			COUNT(CASE WHEN active = TRUE AND usage_last_hour >= rate_limit_per_hour * 0.9 AND usage_last_hour < rate_limit_per_hour THEN 1 END) as approaching_limit_keys,
			SUM(CASE WHEN active = TRUE THEN usage_last_hour ELSE 0 END) as total_requests_last_hour,
			AVG(CASE WHEN active = TRUE THEN (usage_last_hour / rate_limit_per_hour) * 100 ELSE 0 END) as avg_utilization_percent,
			MAX(CASE WHEN active = TRUE THEN (usage_last_hour / rate_limit_per_hour) * 100 ELSE 0 END) as max_utilization_percent
		FROM API_Key_Usage_Last_Hour`

	var metrics struct {
		TotalAPIKeys          int     `db:"total_api_keys"`
		ActiveAPIKeys         int     `db:"active_api_keys"`
		RateLimitedKeys       int     `db:"rate_limited_keys"`
		ApproachingLimitKeys  int     `db:"approaching_limit_keys"`
		TotalRequestsLastHour int64   `db:"total_requests_last_hour"`
		AvgUtilizationPercent float64 `db:"avg_utilization_percent"`
		MaxUtilizationPercent float64 `db:"max_utilization_percent"`
	}

	err := h.db.Get(&metrics, metricsQuery)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Error getting metrics", err.Error())
		return
	}

	// Get top API keys by usage
	topUsageQuery := `
		SELECT api_key_id, key_name, key_prefix, usage_last_hour, rate_limit_per_hour
		FROM API_Key_Usage_Last_Hour 
		WHERE active = TRUE 
		ORDER BY usage_last_hour DESC 
		LIMIT 10`

	rows, err := h.db.Query(topUsageQuery)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Error getting top usage", err.Error())
		return
	}
	defer rows.Close()

	var topUsage []map[string]interface{}
	for rows.Next() {
		var apiKeyID, usageLastHour, rateLimitPerHour int
		var keyName, keyPrefix string
		
		err := rows.Scan(&apiKeyID, &keyName, &keyPrefix, &usageLastHour, &rateLimitPerHour)
		if err != nil {
			continue
		}

		topUsage = append(topUsage, map[string]interface{}{
			"api_key_id":         apiKeyID,
			"key_name":          keyName,
			"key_prefix":        keyPrefix,
			"usage_last_hour":   usageLastHour,
			"rate_limit_per_hour": rateLimitPerHour,
			"utilization_percent": float64(usageLastHour) / float64(rateLimitPerHour) * 100,
		})
	}

	response := map[string]interface{}{
		"summary": map[string]interface{}{
			"total_api_keys":           metrics.TotalAPIKeys,
			"active_api_keys":          metrics.ActiveAPIKeys,
			"rate_limited_keys":        metrics.RateLimitedKeys,
			"approaching_limit_keys":   metrics.ApproachingLimitKeys,
			"total_requests_last_hour": metrics.TotalRequestsLastHour,
			"avg_utilization_percent":  metrics.AvgUtilizationPercent,
			"max_utilization_percent":  metrics.MaxUtilizationPercent,
		},
		"top_usage_api_keys": topUsage,
		"timestamp":          getCurrentTimestamp(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper functions

// writeErrorResponse writes a JSON error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, message, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":     message,
		"status":    statusCode,
		"timestamp": time.Now().Unix(),
	}
	
	if detail != "" {
		response["detail"] = detail
	}
	
	json.NewEncoder(w).Encode(response)
}

// getCurrentTimestamp returns current Unix timestamp
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

func (h *RateLimitHandler) calculateRateLimitSummary(statuses []RateLimitStatus) APIKeyRateLimitSummary {
	summary := APIKeyRateLimitSummary{}
	
	for _, status := range statuses {
		summary.TotalAPIKeys++
		if status.Active {
			summary.ActiveAPIKeys++
		}
		if status.Status == "RATE_LIMITED" {
			summary.RateLimitedKeys++
		}
		if status.Status == "APPROACHING_LIMIT" {
			summary.ApproachingLimitKeys++
		}
		summary.TotalRequestsLastHour += int64(status.UsageLastHour)
	}
	
	return summary
}

func (h *RateLimitHandler) getDetailedUsageStats(apiKeyID int) (map[string]interface{}, error) {
	query := `
		SELECT 
			COUNT(*) as total_requests,
			COUNT(CASE WHEN response_status >= 200 AND response_status < 300 THEN 1 END) as successful_requests,
			COUNT(CASE WHEN response_status >= 400 THEN 1 END) as error_requests,
			COUNT(CASE WHEN response_status = 429 THEN 1 END) as rate_limited_requests,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as requests_last_24h,
			COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as requests_last_7d,
			AVG(response_time_ms) as avg_response_time_ms,
			MAX(created_at) as last_request_time
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ?`
	
	var stats struct {
		TotalRequests        int64    `db:"total_requests"`
		SuccessfulRequests   int64    `db:"successful_requests"`
		ErrorRequests        int64    `db:"error_requests"`
		RateLimitedRequests  int64    `db:"rate_limited_requests"`
		RequestsLast24h      int64    `db:"requests_last_24h"`
		RequestsLast7d       int64    `db:"requests_last_7d"`
		AvgResponseTimeMs    *float64 `db:"avg_response_time_ms"`
		LastRequestTime      *string  `db:"last_request_time"`
	}

	err := h.db.Get(&stats, query, apiKeyID)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"total_requests":        stats.TotalRequests,
		"successful_requests":   stats.SuccessfulRequests,
		"error_requests":        stats.ErrorRequests,
		"rate_limited_requests": stats.RateLimitedRequests,
		"requests_last_24h":     stats.RequestsLast24h,
		"requests_last_7d":      stats.RequestsLast7d,
		"last_request_time":     stats.LastRequestTime,
	}

	if stats.AvgResponseTimeMs != nil {
		result["avg_response_time_ms"] = *stats.AvgResponseTimeMs
	}

	// Calculate success rate
	if stats.TotalRequests > 0 {
		result["success_rate_percent"] = float64(stats.SuccessfulRequests) / float64(stats.TotalRequests) * 100
		result["error_rate_percent"] = float64(stats.ErrorRequests) / float64(stats.TotalRequests) * 100
	}

	return result, nil
}
