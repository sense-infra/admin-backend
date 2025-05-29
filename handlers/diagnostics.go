package handlers

import (
    "context"
    "database/sql"
    "net/http"
    "time"
)

// DatabaseDiagnostics provides detailed database diagnostics
func (h *Handler) DatabaseDiagnostics(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
    defer cancel()
    
    diag := map[string]interface{}{
        "timestamp": time.Now().Format(time.RFC3339),
    }
    
    // 1. Basic connectivity test
    pingStart := time.Now()
    if err := h.db.PingContext(ctx); err != nil {
        diag["ping"] = map[string]interface{}{
            "status": "failed",
            "error": err.Error(),
            "latency_ms": time.Since(pingStart).Milliseconds(),
        }
    } else {
        diag["ping"] = map[string]interface{}{
            "status": "ok",
            "latency_ms": time.Since(pingStart).Milliseconds(),
        }
    }
    
    // 2. Simple query test
    queryStart := time.Now()
    var result int
    err := h.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
    if err != nil {
        diag["simple_query"] = map[string]interface{}{
            "status": "failed",
            "error": err.Error(),
            "latency_ms": time.Since(queryStart).Milliseconds(),
        }
    } else {
        diag["simple_query"] = map[string]interface{}{
            "status": "ok",
            "result": result,
            "latency_ms": time.Since(queryStart).Milliseconds(),
        }
    }
    
    // 3. Customer count
    countStart := time.Now()
    var customerCount int
    err = h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM Customer").Scan(&customerCount)
    if err != nil {
        diag["customer_count"] = map[string]interface{}{
            "status": "failed",
            "error": err.Error(),
            "latency_ms": time.Since(countStart).Milliseconds(),
        }
    } else {
        diag["customer_count"] = map[string]interface{}{
            "status": "ok",
            "count": customerCount,
            "latency_ms": time.Since(countStart).Milliseconds(),
        }
    }
    
    // 4. Connection pool stats
    stats := h.db.Stats()
    diag["connection_pool"] = map[string]interface{}{
        "open_connections": stats.OpenConnections,
        "in_use": stats.InUse,
        "idle": stats.Idle,
        "wait_count": stats.WaitCount,
        "wait_duration_ms": stats.WaitDuration.Milliseconds(),
        "max_idle_closed": stats.MaxIdleClosed,
        "max_lifetime_closed": stats.MaxLifetimeClosed,
    }
    
    // 5. Database variables
    vars := make(map[string]string)
    rows, err := h.db.QueryContext(ctx, "SHOW VARIABLES LIKE 'max_connections'")
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var name, value string
            if err := rows.Scan(&name, &value); err == nil {
                vars[name] = value
            }
        }
    }
    diag["database_variables"] = vars
    
    // 6. Test transaction isolation
    tx, err := h.db.BeginTx(ctx, &sql.TxOptions{
        Isolation: sql.LevelReadCommitted,
        ReadOnly:  true,
    })
    if err != nil {
        diag["transaction_test"] = map[string]interface{}{
            "status": "failed",
            "error": err.Error(),
        }
    } else {
        tx.Rollback()
        diag["transaction_test"] = map[string]interface{}{
            "status": "ok",
            "isolation_level": "READ_COMMITTED",
        }
    }
    
    respondJSON(w, http.StatusOK, diag)
}
