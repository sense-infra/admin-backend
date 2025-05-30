package db

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sense-security/api/config"
)

func Init(cfg config.DatabaseConfig) (*sqlx.DB, error) {
	// Build connection string using the DatabaseConfig struct
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name)

	db, err := sqlx.Connect("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Printf("Connected to MariaDB database: %s@%s:%s/%s", 
		cfg.User, cfg.Host, cfg.Port, cfg.Name)

	return db, nil
}

func Close(db *sqlx.DB) error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// HealthCheck performs a simple health check on the database
func HealthCheck(db *sqlx.DB) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}

	var result int
	err := db.Get(&result, "SELECT 1")
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}

// GetDBStats returns database connection statistics
func GetDBStats(db *sqlx.DB) sql.DBStats {
	return db.Stats()
}
