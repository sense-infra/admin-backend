package main

import (
	"log"
	"net/http"
	"os"

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

	// Setup router
	r := mux.NewRouter()

	// Add CORS middleware to all routes
	r.Use(authMiddleware.CORS)
	r.Use(authMiddleware.LogAPIUsage)

	// API routes (no version prefix - handled at infra level)
	api := r.PathPrefix("/api").Subrouter()

	// Health check endpoint (public)
	api.HandleFunc("/health", healthHandler.GetHealth).Methods("GET")

	// ========================================
	// AUTHENTICATION ROUTES
	// ========================================
	
	// Public auth routes (no authentication required)
	api.HandleFunc("/auth/login", authHandler.Login).Methods("POST")

	// Protected auth routes (require authentication)
	authRoutes := api.PathPrefix("/auth").Subrouter()
	authRoutes.Use(authMiddleware.RequireAuth)
	
	authRoutes.HandleFunc("/profile", authHandler.GetProfile).Methods("GET")
	authRoutes.HandleFunc("/logout", authHandler.Logout).Methods("POST")
	authRoutes.HandleFunc("/change-password", authHandler.ChangePassword).Methods("PUT") // Fixed: should be PUT, not POST

	// ========================================
	// USER MANAGEMENT ROUTES (ADMIN)
	// ========================================
	
	// User read operations
	userReadRoutes := api.PathPrefix("/auth").Subrouter()
	userReadRoutes.Use(authMiddleware.RequireAuth)
	userReadRoutes.Use(authMiddleware.RequirePermission("users", "read"))
	
	userReadRoutes.HandleFunc("/users", authHandler.GetUsers).Methods("GET")
	userReadRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.GetUser).Methods("GET")
	userReadRoutes.HandleFunc("/roles", authHandler.GetRoles).Methods("GET")

	// User create operations
	userCreateRoutes := api.PathPrefix("/auth").Subrouter()
	userCreateRoutes.Use(authMiddleware.RequireAuth)
	userCreateRoutes.Use(authMiddleware.RequirePermission("users", "create"))
	
	userCreateRoutes.HandleFunc("/users", authHandler.CreateUser).Methods("POST")

	// User update operations
	userUpdateRoutes := api.PathPrefix("/auth").Subrouter()
	userUpdateRoutes.Use(authMiddleware.RequireAuth)
	userUpdateRoutes.Use(authMiddleware.RequirePermission("users", "update"))
	
	userUpdateRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.UpdateUser).Methods("PUT")

	// User delete operations
	userDeleteRoutes := api.PathPrefix("/auth").Subrouter()
	userDeleteRoutes.Use(authMiddleware.RequireAuth)
	userDeleteRoutes.Use(authMiddleware.RequirePermission("users", "delete"))
	
	userDeleteRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.DeleteUser).Methods("DELETE")

	// ========================================
	// API KEY MANAGEMENT ROUTES (ADMIN)
	// ========================================
	
	// API Key read operations
	apiKeyReadRoutes := api.PathPrefix("/auth").Subrouter()
	apiKeyReadRoutes.Use(authMiddleware.RequireAuth)
	apiKeyReadRoutes.Use(authMiddleware.RequirePermission("api_keys", "read"))
	
	apiKeyReadRoutes.HandleFunc("/api-keys", authHandler.GetAPIKeys).Methods("GET")
	apiKeyReadRoutes.HandleFunc("/api-keys/{id:[0-9]+}", authHandler.GetAPIKey).Methods("GET")
	apiKeyReadRoutes.HandleFunc("/api-keys/{id:[0-9]+}/usage", authHandler.GetAPIKeyUsage).Methods("GET")

	// API Key create operations
	apiKeyCreateRoutes := api.PathPrefix("/auth").Subrouter()
	apiKeyCreateRoutes.Use(authMiddleware.RequireAuth)
	apiKeyCreateRoutes.Use(authMiddleware.RequirePermission("api_keys", "create"))
	
	apiKeyCreateRoutes.HandleFunc("/api-keys", authHandler.CreateAPIKey).Methods("POST")

	// API Key update operations
	apiKeyUpdateRoutes := api.PathPrefix("/auth").Subrouter()
	apiKeyUpdateRoutes.Use(authMiddleware.RequireAuth)
	apiKeyUpdateRoutes.Use(authMiddleware.RequirePermission("api_keys", "update"))
	
	apiKeyUpdateRoutes.HandleFunc("/api-keys/{id:[0-9]+}", authHandler.UpdateAPIKey).Methods("PUT")

	// API Key delete operations
	apiKeyDeleteRoutes := api.PathPrefix("/auth").Subrouter()
	apiKeyDeleteRoutes.Use(authMiddleware.RequireAuth)
	apiKeyDeleteRoutes.Use(authMiddleware.RequirePermission("api_keys", "delete"))
	
	apiKeyDeleteRoutes.HandleFunc("/api-keys/{id:[0-9]+}", authHandler.DeleteAPIKey).Methods("DELETE")

	// ========================================
	// CUSTOMER MANAGEMENT ROUTES
	// ========================================
	
	// Customer read operations
	customerReadRoutes := api.PathPrefix("/customers").Subrouter()
	customerReadRoutes.Use(authMiddleware.RequireAuth)
	customerReadRoutes.Use(authMiddleware.RequirePermission("customers", "read"))
	
	customerReadRoutes.HandleFunc("", customerHandler.GetCustomers).Methods("GET")
	customerReadRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.GetCustomer).Methods("GET")

	// Customer create operations
	customerCreateRoutes := api.PathPrefix("/customers").Subrouter()
	customerCreateRoutes.Use(authMiddleware.RequireAuth)
	customerCreateRoutes.Use(authMiddleware.RequirePermission("customers", "create"))
	
	customerCreateRoutes.HandleFunc("", customerHandler.CreateCustomer).Methods("POST")

	// Customer update operations
	customerUpdateRoutes := api.PathPrefix("/customers").Subrouter()
	customerUpdateRoutes.Use(authMiddleware.RequireAuth)
	customerUpdateRoutes.Use(authMiddleware.RequirePermission("customers", "update"))
	
	customerUpdateRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.UpdateCustomer).Methods("PUT")

	// Customer delete operations
	customerDeleteRoutes := api.PathPrefix("/customers").Subrouter()
	customerDeleteRoutes.Use(authMiddleware.RequireAuth)
	customerDeleteRoutes.Use(authMiddleware.RequirePermission("customers", "delete"))
	
	customerDeleteRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.DeleteCustomer).Methods("DELETE")

	// ========================================
	// CONTRACT MANAGEMENT ROUTES
	// ========================================
	
	// Contract read operations
	contractReadRoutes := api.PathPrefix("/contracts").Subrouter()
	contractReadRoutes.Use(authMiddleware.RequireAuth)
	contractReadRoutes.Use(authMiddleware.RequirePermission("contracts", "read"))
	
	contractReadRoutes.HandleFunc("", contractHandler.GetContracts).Methods("GET")
	contractReadRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.GetContract).Methods("GET")

	// Contract create operations
	contractCreateRoutes := api.PathPrefix("/contracts").Subrouter()
	contractCreateRoutes.Use(authMiddleware.RequireAuth)
	contractCreateRoutes.Use(authMiddleware.RequirePermission("contracts", "create"))
	
	contractCreateRoutes.HandleFunc("", contractHandler.CreateContract).Methods("POST")

	// Contract update operations
	contractUpdateRoutes := api.PathPrefix("/contracts").Subrouter()
	contractUpdateRoutes.Use(authMiddleware.RequireAuth)
	contractUpdateRoutes.Use(authMiddleware.RequirePermission("contracts", "update"))
	
	contractUpdateRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.UpdateContract).Methods("PUT")

	// Contract delete operations
	contractDeleteRoutes := api.PathPrefix("/contracts").Subrouter()
	contractDeleteRoutes.Use(authMiddleware.RequireAuth)
	contractDeleteRoutes.Use(authMiddleware.RequirePermission("contracts", "delete"))
	
	contractDeleteRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.DeleteContract).Methods("DELETE")

	// ========================================
	// DIAGNOSTICS ROUTES (ADMIN ONLY)
	// ========================================
	
	diagnosticsRoutes := api.PathPrefix("/diagnostics").Subrouter()
	diagnosticsRoutes.Use(authMiddleware.RequireAuth)
	diagnosticsRoutes.Use(authMiddleware.RequireRole("admin"))
	
	diagnosticsRoutes.HandleFunc("/db-status", diagnosticsHandler.GetDatabaseStatus).Methods("GET")
	diagnosticsRoutes.HandleFunc("/system-info", diagnosticsHandler.GetSystemInfo).Methods("GET")

	// ========================================
	// STATIC FILE SERVING
	// ========================================
	
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

	// ========================================
	// START SERVER
	// ========================================
	
	// Clean up port configuration - remove any leading colons
	port := cfg.Server.Port
	if port == "" {
		port = "8080" // default port
	}
	// Remove any leading colons
	if port[0] == ':' {
		port = port[1:]
	}
	
	log.Printf("Starting server on port %s", port)
	log.Printf("Admin interface: http://localhost:%s", port)
	log.Printf("API base URL: http://localhost:%s/api", port)
	log.Printf("Health check: http://localhost:%s/api/health", port)
	log.Printf("Login endpoint: http://localhost:%s/api/auth/login", port)
	log.Printf("Default admin credentials: admin / SenseGuard2025!")
	log.Printf("Default viewer credentials: viewer / Viewer2025!")
	
	serverAddr := ":" + port
	log.Printf("Binding to address: %s", serverAddr)
	
	if err := http.ListenAndServe(serverAddr, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
