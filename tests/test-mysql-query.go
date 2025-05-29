package main

import (
    "database/sql"
    "fmt"
    "log"
    "time"
    _ "github.com/go-sql-driver/mysql"
)

func main() {
    // Direct connection test
    dsn := "admin:changeme@tcp(dev-mariadb-ms.dev:3306)/dev?parseTime=true&timeout=30s&readTimeout=30s&writeTimeout=30s"
    
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal("Failed to open database:", err)
    }
    defer db.Close()
    
    // Set connection pool settings
    db.SetMaxOpenConns(5)
    db.SetMaxIdleConns(2)
    db.SetConnMaxLifetime(5 * time.Minute)
    
    // Test 10 times
    for i := 0; i < 10; i++ {
        fmt.Printf("\nTest %d:\n", i+1)
        
        // Count customers
        var count int
        err := db.QueryRow("SELECT COUNT(*) FROM Customer").Scan(&count)
        if err != nil {
            log.Printf("Count failed: %v", err)
            continue
        }
        fmt.Printf("  Total customers: %d\n", count)
        
        // Fetch customers
        start := time.Now()
        rows, err := db.Query("SELECT customer_id, name_on_contract FROM Customer ORDER BY customer_id DESC LIMIT 1")
        if err != nil {
            log.Printf("Query failed: %v", err)
            continue
        }
        
        queryTime := time.Since(start)
        fmt.Printf("  Query time: %v\n", queryTime)
        
        rowCount := 0
        for rows.Next() {
            var id int
            var name string
            if err := rows.Scan(&id, &name); err != nil {
                log.Printf("Scan failed: %v", err)
                break
            }
            rowCount++
            fmt.Printf("  Found: ID=%d, Name=%s\n", id, name)
        }
        rows.Close()
        
        if err := rows.Err(); err != nil {
            log.Printf("Rows error: %v", err)
        }
        
        fmt.Printf("  Fetched %d rows\n", rowCount)
        
        time.Sleep(2 * time.Second)
    }
}
