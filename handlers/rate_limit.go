package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/sense-security/api/middleware"
	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
)

// RateLimitHandler handles rate limit related requests
type RateLimitHandler struct {
	*BaseHandler
	authService *services.AuthService
}

func NewRateLimitHandler(database *sqlx.DB, authService *services.AuthService) *RateLimitHandler {
	return &RateLimitHandler{
		BaseHandler: NewBaseHandler(database),
		authService: authService,
	}
}

// GetAPIKeyRateLimit returns rate limit information for an API key
func (h *RateLimitHandler) GetAPIKeyRateLimit(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	// Check permissions
	if !middleware.HasPermission(r, "api_keys", "read") {
		WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "")
		return
	}

	rateLimitInfo, err := h.authService.GetRateLimitInfo(apiKeyID)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get rate limit info", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, rateLimitInfo)
}

// GetAPIKeyUsage returns usage statistics for an API key
func (h *RateLimitHandler) GetAPIKeyUsage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	// Check permissions
	if !middleware.HasPermission(r, "api_keys", "read") {
		WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "")
		return
	}

	// Get query parameters for filtering
	days := 7 // Default to last 7 days
	if d := r.URL.Query().Get("days"); d != "" {
		if parsedDays, err := strconv.Atoi(d); err == nil && parsedDays > 0 && parsedDays <= 90 {
			days = parsedDays
		}
	}

	usage, err := h.getAPIKeyUsageStats(apiKeyID, days)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get usage statistics", err.Error())
		return
	}

	WriteJSONResponse(w, http.StatusOK, usage)
}

// GetAPIKeyUsageLogs returns detailed usage logs for an API key
func (h *RateLimitHandler) GetAPIKeyUsageLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiKeyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid API key ID", err.Error())
		return
	}

	// Check permissions
	if !middleware.HasPermission(r, "api_keys", "read") {
		WriteErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "")
		return
	}

	// Get pagination parameters
	limit := 100 // Default limit
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsedOffset, err := strconv.Atoi(o); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	logs, total, err := h.getAPIKeyUsageLogs(apiKeyID, limit, offset)
	if err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get usage logs", err.Error())
		return
	}

	response := map[string]interface{}{
		"logs":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}

	WriteJSONResponse(w, http.StatusOK, response)
}

// Helper struct for usage statistics
type APIKeyUsageStats struct {
	APIKeyID      int                    `json:"api_key_id"`
	KeyName       string                 `json:"key_name"`
	TotalRequests int64                  `json:"total_requests"`
	SuccessRate   float64                `json:"success_rate"`
	AvgResponse   float64                `json:"avg_response_time_ms"`
	DailyUsage    []DailyUsage           `json:"daily_usage"`
	TopEndpoints  []EndpointUsage        `json:"top_endpoints"`
	ErrorSummary  []ErrorSummary         `json:"error_summary"`
	Period        string                 `json:"period"`
}

type DailyUsage struct {
	Date     string `json:"date"`
	Requests int    `json:"requests"`
	Errors   int    `json:"errors"`
}

type EndpointUsage struct {
	Endpoint string  `json:"endpoint"`
	Method   string  `json:"method"`
	Count    int     `json:"count"`
	AvgTime  float64 `json:"avg_response_time_ms"`
}

type ErrorSummary struct {
	StatusCode int `json:"status_code"`
	Count      int `json:"count"`
}

func (h *RateLimitHandler) getAPIKeyUsageStats(apiKeyID int, days int) (*APIKeyUsageStats, error) {
	// Get API key info
	apiKey, err := h.authService.GetAPIKeyByID(apiKeyID)
	if err != nil {
		return nil, err
	}

	stats := &APIKeyUsageStats{
		APIKeyID: apiKeyID,
		KeyName:  apiKey.KeyName,
		Period:   fmt.Sprintf("Last %d days", days),
	}

	// Get total requests and success rate
	query := `
		SELECT 
			COUNT(*) as total_requests,
			AVG(CASE WHEN response_status >= 200 AND response_status < 400 THEN 1.0 ELSE 0.0 END) as success_rate,
			AVG(COALESCE(response_time_ms, 0)) as avg_response_time
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ? 
		AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
	`
	
	err = h.db.QueryRow(query, apiKeyID, days).Scan(&stats.TotalRequests, &stats.SuccessRate, &stats.AvgResponse)
	if err != nil {
		return nil, err
	}

	// Get daily usage
	dailyQuery := `
		SELECT 
			DATE(created_at) as date,
			COUNT(*) as requests,
			SUM(CASE WHEN response_status >= 400 THEN 1 ELSE 0 END) as errors
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ? 
		AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
		GROUP BY DATE(created_at)
		ORDER BY date ASC
	`
	
	rows, err := h.db.Query(dailyQuery, apiKeyID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var usage DailyUsage
		err := rows.Scan(&usage.Date, &usage.Requests, &usage.Errors)
		if err != nil {
			return nil, err
		}
		stats.DailyUsage = append(stats.DailyUsage, usage)
	}

	// Get top endpoints
	endpointQuery := `
		SELECT 
			endpoint, method,
			COUNT(*) as count,
			AVG(COALESCE(response_time_ms, 0)) as avg_time
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ? 
		AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
		GROUP BY endpoint, method
		ORDER BY count DESC
		LIMIT 10
	`
	
	rows, err = h.db.Query(endpointQuery, apiKeyID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var endpoint EndpointUsage
		err := rows.Scan(&endpoint.Endpoint, &endpoint.Method, &endpoint.Count, &endpoint.AvgTime)
		if err != nil {
			return nil, err
		}
		stats.TopEndpoints = append(stats.TopEndpoints, endpoint)
	}

	// Get error summary
	errorQuery := `
		SELECT 
			response_status,
			COUNT(*) as count
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ? 
		AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
		AND response_status >= 400
		GROUP BY response_status
		ORDER BY count DESC
	`
	
	rows, err = h.db.Query(errorQuery, apiKeyID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var errorSum ErrorSummary
		err := rows.Scan(&errorSum.StatusCode, &errorSum.Count)
		if err != nil {
			return nil, err
		}
		stats.ErrorSummary = append(stats.ErrorSummary, errorSum)
	}

	return stats, nil
}

func (h *RateLimitHandler) getAPIKeyUsageLogs(apiKeyID, limit, offset int) ([]models.APIKeyUsageLog, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM API_Key_Usage_Log WHERE api_key_id = ?`
	err := h.db.QueryRow(countQuery, apiKeyID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get logs
	query := `
		SELECT 
			log_id, api_key_id, endpoint, method, ip_address, user_agent,
			response_status, response_time_ms, request_size_bytes, response_size_bytes, created_at
		FROM API_Key_Usage_Log 
		WHERE api_key_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`
	
	rows, err := h.db.Query(query, apiKeyID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []models.APIKeyUsageLog
	for rows.Next() {
		var log models.APIKeyUsageLog
		err := rows.Scan(
			&log.LogID, &log.APIKeyID, &log.Endpoint, &log.Method,
			&log.IPAddress, &log.UserAgent, &log.ResponseStatus,
			&log.ResponseTimeMs, &log.RequestSizeBytes, &log.ResponseSizeBytes,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, log)
	}

	return logs, total, nil
}
