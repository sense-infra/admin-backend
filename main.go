package main

import (
        "log"
        "net/http"
        "os"
        "strings"

        "github.com/gorilla/mux"
        "github.com/joho/godotenv"
        "github.com/sense-security/api/config"
        "github.com/sense-security/api/db"
        "github.com/sense-security/api/handlers"
        "github.com/sense-security/api/middleware"
        "github.com/sense-security/api/services"
)

func main() {
        // Load environment variables
        if err := godotenv.Load(); err != nil {
                log.Println("No .env file found, using system environment variables")
        }

        // Load configuration
        cfg := config.Load()

        // Initialize database
        database, err := db.Init(cfg.Database)
        if err != nil {
                log.Fatalf("Failed to initialize database: %v", err)
        }
        defer database.Close()

        // Initialize services
        authService := services.NewAuthService(database, cfg.JWT.Secret)

        // Initialize middleware
        authMiddleware := middleware.NewAuthMiddleware(authService)

        // Initialize handlers
        healthHandler := handlers.NewHealthHandler(database)
        authHandler := handlers.NewAuthHandler(authService)
        customerHandler := handlers.NewCustomerHandler(database)
        contractHandler := handlers.NewContractHandler(database)
        diagnosticsHandler := handlers.NewDiagnosticsHandler(database)
        rateLimitHandler := handlers.NewRateLimitHandler(database, authService)

        // Setup router
        r := mux.NewRouter()

        // Add CORS middleware to all routes
        r.Use(authMiddleware.CORS)
        r.Use(authMiddleware.LogAPIUsage)
        r.Use(authMiddleware.AddRateLimitHeaders)

        // Public routes (no authentication required)
        r.HandleFunc("/health", healthHandler.GetHealth).Methods("GET")
        r.HandleFunc("/auth/login", authHandler.Login).Methods("POST")

        // Protected routes (authentication required)
        authRoutes := r.PathPrefix("/auth").Subrouter()
        authRoutes.Use(authMiddleware.RequireAuth)
        authRoutes.HandleFunc("/profile", authHandler.GetProfile).Methods("GET")
        authRoutes.HandleFunc("/logout", authHandler.Logout).Methods("POST")
        authRoutes.HandleFunc("/change-password", authHandler.ChangePassword).Methods("POST")

        // Admin-only authentication routes
        adminAuthRoutes := r.PathPrefix("/auth").Subrouter()
        adminAuthRoutes.Use(authMiddleware.RequirePermission("users", "read"))
        adminAuthRoutes.HandleFunc("/users", authHandler.GetUsers).Methods("GET")
        adminAuthRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.GetUser).Methods("GET")
        adminAuthRoutes.HandleFunc("/roles", authHandler.GetRoles).Methods("GET")

        adminAuthCreateRoutes := r.PathPrefix("/auth").Subrouter()
        adminAuthCreateRoutes.Use(authMiddleware.RequirePermission("users", "create"))
        adminAuthCreateRoutes.HandleFunc("/users", authHandler.CreateUser).Methods("POST")

        adminAuthUpdateRoutes := r.PathPrefix("/auth").Subrouter()
        adminAuthUpdateRoutes.Use(authMiddleware.RequirePermission("users", "update"))
        adminAuthUpdateRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.UpdateUser).Methods("PUT")

        adminAuthDeleteRoutes := r.PathPrefix("/auth").Subrouter()
        adminAuthDeleteRoutes.Use(authMiddleware.RequirePermission("users", "delete"))
        adminAuthDeleteRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.DeleteUser).Methods("DELETE")

        // API Key management routes
        apiKeyReadRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
        apiKeyReadRoutes.Use(authMiddleware.RequirePermission("api_keys", "read"))
        apiKeyReadRoutes.HandleFunc("", authHandler.GetAPIKeys).Methods("GET")
        apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}", authHandler.GetAPIKey).Methods("GET")
        apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}/usage", authHandler.GetAPIKeyUsage).Methods("GET")

        // Rate limiting specific routes
        apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}/rate-limit", rateLimitHandler.GetAPIKeyRateLimit).Methods("GET")
        apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}/usage-stats", rateLimitHandler.GetAPIKeyUsage).Methods("GET")
        apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}/logs", rateLimitHandler.GetAPIKeyUsageLogs).Methods("GET")

        apiKeyCreateRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
        apiKeyCreateRoutes.Use(authMiddleware.RequirePermission("api_keys", "create"))
        apiKeyCreateRoutes.HandleFunc("", authHandler.CreateAPIKey).Methods("POST")

        apiKeyUpdateRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
        apiKeyUpdateRoutes.Use(authMiddleware.RequirePermission("api_keys", "update"))
        apiKeyUpdateRoutes.HandleFunc("/{id:[0-9]+}", authHandler.UpdateAPIKey).Methods("PUT")

        apiKeyDeleteRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
        apiKeyDeleteRoutes.Use(authMiddleware.RequirePermission("api_keys", "delete"))
        apiKeyDeleteRoutes.HandleFunc("/{id:[0-9]+}", authHandler.DeleteAPIKey).Methods("DELETE")

        // Customer routes
        customerReadRoutes := r.PathPrefix("/customers").Subrouter()
        customerReadRoutes.Use(authMiddleware.RequirePermission("customers", "read"))
        customerReadRoutes.HandleFunc("", customerHandler.GetCustomers).Methods("GET")
        customerReadRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.GetCustomer).Methods("GET")

        customerCreateRoutes := r.PathPrefix("/customers").Subrouter()
        customerCreateRoutes.Use(authMiddleware.RequirePermission("customers", "create"))
        customerCreateRoutes.HandleFunc("", customerHandler.CreateCustomer).Methods("POST")

        customerUpdateRoutes := r.PathPrefix("/customers").Subrouter()
        customerUpdateRoutes.Use(authMiddleware.RequirePermission("customers", "update"))
        customerUpdateRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.UpdateCustomer).Methods("PUT")

        customerDeleteRoutes := r.PathPrefix("/customers").Subrouter()
        customerDeleteRoutes.Use(authMiddleware.RequirePermission("customers", "delete"))
        customerDeleteRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.DeleteCustomer).Methods("DELETE")

        // Contract routes
        contractReadRoutes := r.PathPrefix("/contracts").Subrouter()
        contractReadRoutes.Use(authMiddleware.RequirePermission("contracts", "read"))
        contractReadRoutes.HandleFunc("", contractHandler.GetContracts).Methods("GET")
        contractReadRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.GetContract).Methods("GET")

        contractCreateRoutes := r.PathPrefix("/contracts").Subrouter()
        contractCreateRoutes.Use(authMiddleware.RequirePermission("contracts", "create"))
        contractCreateRoutes.HandleFunc("", contractHandler.CreateContract).Methods("POST")

        contractUpdateRoutes := r.PathPrefix("/contracts").Subrouter()
        contractUpdateRoutes.Use(authMiddleware.RequirePermission("contracts", "update"))
        contractUpdateRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.UpdateContract).Methods("PUT")

        contractDeleteRoutes := r.PathPrefix("/contracts").Subrouter()
        contractDeleteRoutes.Use(authMiddleware.RequirePermission("contracts", "delete"))
        contractDeleteRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.DeleteContract).Methods("DELETE")

        // Diagnostics routes (admin only)
        diagnosticsRoutes := r.PathPrefix("/diagnostics").Subrouter()
        diagnosticsRoutes.Use(authMiddleware.RequireRole("admin"))
        diagnosticsRoutes.HandleFunc("/db-status", diagnosticsHandler.GetDatabaseStatus).Methods("GET")
        diagnosticsRoutes.HandleFunc("/system-info", diagnosticsHandler.GetSystemInfo).Methods("GET")

        // Serve static files (web interface)
        webDir := "./web/"
        if _, err := os.Stat(webDir); os.IsNotExist(err) {
                log.Println("Web directory not found, creating basic file server")
                r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("./"))))
        } else {
                r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir(webDir))))
        }

        // Handle root path specifically for admin interface
        r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                if r.URL.Path == "/" {
                        // Serve admin interface
                        http.ServeFile(w, r, "./web/admin.html")
                }
        }).Methods("GET")

        // Start server
        port := cfg.Server.Port
        // Remove leading colon if present to avoid double colons
        if strings.HasPrefix(port, ":") {
                port = port[1:]
        }
        
        log.Printf("Starting server on :%s", port)
        log.Printf("Admin interface: http://localhost:%s", port)
        log.Printf("API endpoints:")
        log.Printf("  - Health check: http://localhost:%s/health", port)
        log.Printf("  - Authentication: http://localhost:%s/auth/*", port)
        log.Printf("  - Customers: http://localhost:%s/customers", port)
        log.Printf("  - Contracts: http://localhost:%s/contracts", port)
        log.Printf("  - API Keys: http://localhost:%s/auth/api-keys", port)
        log.Printf("  - Rate Limits: http://localhost:%s/auth/api-keys/{id}/rate-limit", port)
        log.Printf("Default admin credentials: admin / SenseGuard2025!")
        log.Printf("Default viewer credentials: viewer / Viewer2025!")

        if err := http.ListenAndServe(":"+port, r); err != nil {
                log.Fatalf("Server failed to start: %v", err)
        }
}
