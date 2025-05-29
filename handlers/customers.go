package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/models"
)

// ListCustomers returns a list of all customers with extensive debugging
func (h *Handler) ListCustomers(w http.ResponseWriter, r *http.Request) {
	limit, offset := getPaginationParams(r)
	
	log.Printf("ListCustomers called with limit=%d, offset=%d", limit, offset)
	
	// Create a context with timeout for the entire operation
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second) // Increased timeout
	defer cancel()
	
	// Add connection check with context
	pingStart := time.Now()
	if err := h.db.PingContext(ctx); err != nil {
		log.Printf("Database ping failed after %v: %v", time.Since(pingStart), err)
		respondError(w, http.StatusServiceUnavailable, "Database connection error")
		return
	}
	log.Printf("Database ping successful (took %v)", time.Since(pingStart))
	
	// First, let's count total customers for debugging
	var totalCount int
	countStart := time.Now()
	countQuery := `SELECT COUNT(*) FROM Customer`
	err := h.db.QueryRowContext(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		log.Printf("Failed to count customers after %v: %v", time.Since(countStart), err)
	} else {
		log.Printf("Total customers in database: %d (took %v)", totalCount, time.Since(countStart))
	}
	
	// Main query with explicit column selection
	query := `
		SELECT customer_id, name_on_contract, address, unique_id, 
		       COALESCE(email, '') as email, 
		       COALESCE(phone_number, '') as phone_number, 
		       created_at, updated_at
		FROM Customer
		ORDER BY customer_id DESC
		LIMIT ? OFFSET ?
	`
	
	log.Printf("Executing query with LIMIT=%d OFFSET=%d", limit, offset)
	startTime := time.Now()
	
	// Use QueryContext with our timeout context
	rows, err := h.db.QueryContext(ctx, query, limit, offset)
	queryDuration := time.Since(startTime)
	
	if err != nil {
		log.Printf("Query failed after %v: %v", queryDuration, err)
		log.Printf("Context error: %v", ctx.Err())
		respondError(w, http.StatusInternalServerError, "Failed to fetch customers")
		return
	}
	
	// IMPORTANT: Ensure rows are closed even on panic
	defer func() {
		closeStart := time.Now()
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows after %v: %v", time.Since(closeStart), err)
		} else {
			log.Printf("Rows closed successfully after %v", time.Since(closeStart))
		}
	}()
	
	log.Printf("Query executed successfully (took %v)", queryDuration)
	
	// Check if rows is nil
	if rows == nil {
		log.Printf("ERROR: rows is nil after successful query!")
		respondError(w, http.StatusInternalServerError, "Query returned nil rows")
		return
	}
	
	// Initialize customers slice
	customers := make([]models.Customer, 0, limit)
	count := 0
	
	// Check columns for debugging
	columns, err := rows.Columns()
	if err != nil {
		log.Printf("Failed to get columns: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get result columns")
		return
	}
	log.Printf("Query returned %d columns: %v", len(columns), columns)
	
	// Check context before starting iteration
	if ctx.Err() != nil {
		log.Printf("Context cancelled before row iteration: %v", ctx.Err())
		respondError(w, http.StatusRequestTimeout, "Request cancelled")
		return
	}
	
	// Track iteration timing
	iterationStart := time.Now()
	var firstRowTime time.Duration
	hasRows := false
	
	log.Printf("Starting row iteration...")
	
	for {
		// Check context on each iteration
		if ctx.Err() != nil {
			log.Printf("Context cancelled during iteration after %d rows: %v", count, ctx.Err())
			break
		}
		
		// Call Next() and log the result
		nextStart := time.Now()
		hasNext := rows.Next()
		nextDuration := time.Since(nextStart)
		
		if !hasNext {
			log.Printf("rows.Next() returned false after %d rows (took %v)", count, nextDuration)
			break
		}
		
		hasRows = true
		if count == 0 {
			firstRowTime = time.Since(iterationStart)
			log.Printf("First row available after %v", firstRowTime)
		}
		
		// Create variables for scanning
		var c models.Customer
		var email, phone sql.NullString
		
		scanStart := time.Now()
		err := rows.Scan(
			&c.CustomerID, 
			&c.NameOnContract, 
			&c.Address, 
			&c.UniqueID,
			&email,
			&phone,
			&c.CreatedAt, 
			&c.UpdatedAt,
		)
		scanDuration := time.Since(scanStart)
		
		if err != nil {
			log.Printf("Scan error on row %d after %v: %v", count+1, scanDuration, err)
			log.Printf("Context state: %v", ctx.Err())
			
			// Try to get the actual error
			if rows.Err() != nil {
				log.Printf("Rows error: %v", rows.Err())
			}
			
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read customer data: %v", err))
			return
		}
		
		// Handle nullable fields
		if email.Valid {
			c.Email = &email.String
		}
		if phone.Valid {
			c.PhoneNumber = &phone.String
		}
		
		customers = append(customers, c)
		count++
		
		// Log first customer for debugging
		if count == 1 {
			log.Printf("First customer scanned: ID=%d, Name=%s (scan took %v)", 
				c.CustomerID, c.NameOnContract, scanDuration)
		}
		
		// Log every 10th row for large result sets
		if count%10 == 0 {
			log.Printf("Scanned %d rows so far...", count)
		}
	}
	
	iterationDuration := time.Since(iterationStart)
	log.Printf("Row iteration completed: hasRows=%v, count=%d, duration=%v", hasRows, count, iterationDuration)
	
	// Check for errors from iterating over rows
	if err = rows.Err(); err != nil {
		log.Printf("rows.Err() after iteration: %v", err)
		log.Printf("Successfully read %d rows before error", count)
		
		// Still return what we got if we have some data
		if count > 0 {
			log.Printf("Returning partial results: %d customers", count)
		} else {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("Error reading results: %v", err))
			return
		}
	}
	
	// Final check
	if !hasRows && totalCount > 0 {
		log.Printf("WARNING: No rows returned but COUNT shows %d customers!", totalCount)
		log.Printf("This suggests rows.Next() failed immediately")
		log.Printf("Possible causes: network timeout, result set issue, or connection problem")
	}
	
	log.Printf("Successfully fetched %d customers (total in DB: %d)", count, totalCount)
	log.Printf("Total request processing time: %v", time.Since(startTime))
	
	// Add diagnostic headers
	w.Header().Set("X-Total-Count", strconv.Itoa(totalCount))
	w.Header().Set("X-Returned-Count", strconv.Itoa(count))
	w.Header().Set("X-Query-Time-Ms", strconv.FormatInt(queryDuration.Milliseconds(), 10))
	w.Header().Set("X-Iteration-Time-Ms", strconv.FormatInt(iterationDuration.Milliseconds(), 10))
	if hasRows && firstRowTime > 0 {
		w.Header().Set("X-First-Row-Time-Ms", strconv.FormatInt(firstRowTime.Milliseconds(), 10))
	}
	
	respondJSON(w, http.StatusOK, customers)
}

// Alternative implementation using a different approach
func (h *Handler) ListCustomersBuffered(w http.ResponseWriter, r *http.Request) {
	limit, offset := getPaginationParams(r)
	
	log.Printf("ListCustomersBuffered called with limit=%d, offset=%d", limit, offset)
	
	// Try a simpler approach - load all data at once
	query := `
		SELECT customer_id, name_on_contract, address, unique_id, 
		       email, phone_number, created_at, updated_at
		FROM Customer
		ORDER BY customer_id DESC
		LIMIT ? OFFSET ?
	`
	
	// Create a longer timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	rows, err := h.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		log.Printf("Query error: %v", err)
		respondError(w, http.StatusInternalServerError, "Query failed")
		return
	}
	defer rows.Close()
	
	// Try to read all rows at once
	customers := []models.Customer{}
	for rows.Next() {
		var c models.Customer
		err := rows.Scan(
			&c.CustomerID, &c.NameOnContract, &c.Address, &c.UniqueID,
			&c.Email, &c.PhoneNumber, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		customers = append(customers, c)
	}
	
	if err := rows.Err(); err != nil {
		log.Printf("Rows error: %v", err)
	}
	
	log.Printf("Buffered approach returned %d customers", len(customers))
	respondJSON(w, http.StatusOK, customers)
}

// GetCustomer returns a single customer by ID
func (h *Handler) GetCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	log.Printf("GetCustomer called for ID: %d", id)
	
	var c models.Customer
	query := `
		SELECT customer_id, name_on_contract, address, unique_id, 
		       email, phone_number, created_at, updated_at
		FROM Customer
		WHERE customer_id = ?
	`
	
	err = h.db.QueryRow(query, id).Scan(
		&c.CustomerID, &c.NameOnContract, &c.Address, &c.UniqueID,
		&c.Email, &c.PhoneNumber, &c.CreatedAt, &c.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Customer not found")
		return
	}
	if err != nil {
		log.Printf("Failed to fetch customer %d: %v", id, err)
		respondError(w, http.StatusInternalServerError, "Failed to fetch customer")
		return
	}
	
	respondJSON(w, http.StatusOK, c)
}

// CreateCustomer creates a new customer
func (h *Handler) CreateCustomer(w http.ResponseWriter, r *http.Request) {
	var c models.Customer
	if err := parseJSON(r, &c); err != nil {
		log.Printf("Failed to parse customer JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	if c.NameOnContract == "" || c.Address == "" || c.UniqueID == "" {
		respondError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	
	log.Printf("Creating customer with unique_id: %s", c.UniqueID)
	
	query := `
		INSERT INTO Customer (name_on_contract, address, unique_id, email, phone_number)
		VALUES (?, ?, ?, ?, ?)
	`
	
	result, err := h.db.Exec(query, c.NameOnContract, c.Address, c.UniqueID, c.Email, c.PhoneNumber)
	if err != nil {
		log.Printf("Failed to create customer: %v", err)
		if strings.Contains(err.Error(), "Duplicate entry") {
			respondError(w, http.StatusConflict, "Customer with this unique_id already exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "Failed to create customer")
		return
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get customer ID: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get customer ID")
		return
	}
	
	c.CustomerID = int(id)
	log.Printf("Created customer with ID: %d", c.CustomerID)
	
	// Return the created customer
	w.Header().Set("Location", fmt.Sprintf("/api/customers/%d", c.CustomerID))
	respondJSON(w, http.StatusCreated, c)
}

// UpdateCustomer updates an existing customer
func (h *Handler) UpdateCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	var c models.Customer
	if err := parseJSON(r, &c); err != nil {
		log.Printf("Failed to parse customer JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	if c.NameOnContract == "" || c.Address == "" || c.UniqueID == "" {
		respondError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	
	log.Printf("Updating customer ID: %d", id)
	
	query := `
		UPDATE Customer 
		SET name_on_contract = ?, address = ?, unique_id = ?, 
		    email = ?, phone_number = ?
		WHERE customer_id = ?
	`
	
	result, err := h.db.Exec(query, c.NameOnContract, c.Address, c.UniqueID, 
		c.Email, c.PhoneNumber, id)
	if err != nil {
		log.Printf("Failed to update customer %d: %v", id, err)
		if strings.Contains(err.Error(), "Duplicate entry") {
			respondError(w, http.StatusConflict, "Customer with this unique_id already exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "Failed to update customer")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Failed to check update result: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to check update result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Customer not found")
		return
	}
	
	c.CustomerID = id
	log.Printf("Updated customer ID: %d", id)
	respondJSON(w, http.StatusOK, c)
}

// DeleteCustomer deletes a customer
func (h *Handler) DeleteCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid customer ID")
		return
	}
	
	log.Printf("Deleting customer ID: %d", id)
	
	// Check if customer has any contracts
	var count int
	checkQuery := `
		SELECT COUNT(*) 
		FROM Contract_Customer_Mapping 
		WHERE customer_id = ?
	`
	err = h.db.QueryRow(checkQuery, id).Scan(&count)
	if err != nil {
		log.Printf("Failed to check customer contracts: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to check customer contracts")
		return
	}
	
	if count > 0 {
		log.Printf("Cannot delete customer %d: has %d active contracts", id, count)
		respondError(w, http.StatusConflict, "Cannot delete customer with active contracts")
		return
	}
	
	query := `DELETE FROM Customer WHERE customer_id = ?`
	result, err := h.db.Exec(query, id)
	if err != nil {
		log.Printf("Failed to delete customer %d: %v", id, err)
		respondError(w, http.StatusInternalServerError, "Failed to delete customer")
		return
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Failed to check delete result: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to check delete result")
		return
	}
	
	if rowsAffected == 0 {
		respondError(w, http.StatusNotFound, "Customer not found")
		return
	}
	
	log.Printf("Deleted customer ID: %d", id)
	respondJSON(w, http.StatusNoContent, nil)
}
