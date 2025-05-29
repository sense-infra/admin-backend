package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sense-security/api/config"
)

// DB wraps the SQL database connection
type DB struct {
	*sql.DB
}

// Initialize creates and configures the database connection
func Initialize(cfg config.DatabaseConfig) (*DB, error) {
	// Build DSN with proper parameters
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=Local&charset=utf8mb4&collation=utf8mb4_unicode_ci&timeout=10s&readTimeout=10s&writeTimeout=10s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database)
	
	log.Printf("Connecting to database at %s:%d", cfg.Host, cfg.Port)
	
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	// Reduced pool size to avoid connection issues
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	// Verify connection with retry logic
	var lastErr error
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()
		
		if err == nil {
			log.Println("Database connection established successfully")
			return &DB{db}, nil
		}
		
		lastErr = err
		log.Printf("Database ping attempt %d failed: %v", i+1, err)
		time.Sleep(time.Second * 2)
	}
	
	return nil, fmt.Errorf("failed to ping database after 3 attempts: %w", lastErr)
}

// Query wraps sql.DB.Query with error logging
func (db *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	start := time.Now()
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		log.Printf("Query error (took %v): %v\nQuery: %s\nArgs: %v", 
			time.Since(start), err, query, args)
		return nil, err
	}
	log.Printf("Query executed successfully (took %v)", time.Since(start))
	return rows, nil
}

// QueryRow wraps sql.DB.QueryRow with logging
func (db *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	start := time.Now()
	row := db.DB.QueryRow(query, args...)
	log.Printf("QueryRow executed (took %v)", time.Since(start))
	return row
}

// Exec wraps sql.DB.Exec with error logging
func (db *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	result, err := db.DB.Exec(query, args...)
	if err != nil {
		log.Printf("Exec error (took %v): %v\nQuery: %s\nArgs: %v", 
			time.Since(start), err, query, args)
		return nil, err
	}
	log.Printf("Exec executed successfully (took %v)", time.Since(start))
	return result, nil
}

// Transaction executes a function within a database transaction
func (db *DB) Transaction(fn func(*sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %v", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	
	return nil
}

// HealthCheck performs a health check on the database
func (db *DB) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	var result int
	err := db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	
	if result != 1 {
		return fmt.Errorf("health check returned unexpected result: %d", result)
	}
	
	return nil
}
