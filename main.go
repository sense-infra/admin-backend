package main

import (
	"log"
	"net/http"
	"os"
	"time"

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
	healthHandler := handlers.NewImprovedHealthHandler(database)
	authHandler := handlers.NewAuthHandler(authService)
	customerHandler := handlers.NewCustomerHandler(database)
	contractHandler := handlers.NewContractHandler(database)
	diagnosticsHandler := handlers.NewDiagnosticsHandler(database)

	// Setup router
	r := mux.NewRouter()

	// Add CORS middleware to all routes
	r.Use(authMiddleware.CORS)
	r.Use(authMiddleware.LogAPIUsage)

	// Public routes with rate limiting for security
	
	// Health endpoint with rate limiting (10 requests per minute per IP)
	healthRoutes := r.PathPrefix("/health").Subrouter()
	healthRoutes.Use(middleware.RateLimit(10, time.Minute))
	healthRoutes.HandleFunc("", healthHandler.GetDetailedHealth).Methods("GET")
	
	// Login endpoint with stricter rate limiting (5 attempts per minute per IP)
	loginRoutes := r.PathPrefix("/auth").Subrouter()
	loginRoutes.Use(middleware.RateLimit(5, time.Minute))
	loginRoutes.HandleFunc("/login", authHandler.Login).Methods("POST")

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

	adminAuthRoutes.Use(authMiddleware.RequirePermission("users", "create"))
	adminAuthRoutes.HandleFunc("/users", authHandler.CreateUser).Methods("POST")

	adminAuthRoutes.Use(authMiddleware.RequirePermission("users", "update"))
	adminAuthRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.UpdateUser).Methods("PUT")

	adminAuthRoutes.Use(authMiddleware.RequirePermission("users", "delete"))
	adminAuthRoutes.HandleFunc("/users/{id:[0-9]+}", authHandler.DeleteUser).Methods("DELETE")

	// API Key management routes
	apiKeyRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
	apiKeyRoutes.Use(authMiddleware.RequirePermission("api_keys", "read"))
	apiKeyRoutes.HandleFunc("", authHandler.GetAPIKeys).Methods("GET")
	apiKeyRoutes.HandleFunc("/{id:[0-9]+}", authHandler.GetAPIKey).Methods("GET")
	apiKeyRoutes.HandleFunc("/{id:[0-9]+}/usage", authHandler.GetAPIKeyUsage).Methods("GET")

	apiKeyRoutes.Use(authMiddleware.RequirePermission("api_keys", "create"))
	apiKeyRoutes.HandleFunc("", authHandler.CreateAPIKey).Methods("POST")

	apiKeyRoutes.Use(authMiddleware.RequirePermission("api_keys", "update"))
	apiKeyRoutes.HandleFunc("/{id:[0-9]+}", authHandler.UpdateAPIKey).Methods("PUT")

	apiKeyRoutes.Use(authMiddleware.RequirePermission("api_keys", "delete"))
	apiKeyRoutes.HandleFunc("/{id:[0-9]+}", authHandler.DeleteAPIKey).Methods("DELETE")

	// Customer routes
	customerRoutes := r.PathPrefix("/customers").Subrouter()
	customerRoutes.Use(authMiddleware.RequirePermission("customers", "read"))
	customerRoutes.HandleFunc("", customerHandler.GetCustomers).Methods("GET")
	customerRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.GetCustomer).Methods("GET")

	customerRoutes.Use(authMiddleware.RequirePermission("customers", "create"))
	customerRoutes.HandleFunc("", customerHandler.CreateCustomer).Methods("POST")

	customerRoutes.Use(authMiddleware.RequirePermission("customers", "update"))
	customerRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.UpdateCustomer).Methods("PUT")

	customerRoutes.Use(authMiddleware.RequirePermission("customers", "delete"))
	customerRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.DeleteCustomer).Methods("DELETE")

	// Contract routes
	contractRoutes := r.PathPrefix("/contracts").Subrouter()
	contractRoutes.Use(authMiddleware.RequirePermission("contracts", "read"))
	contractRoutes.HandleFunc("", contractHandler.GetContracts).Methods("GET")
	contractRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.GetContract).Methods("GET")

	contractRoutes.Use(authMiddleware.RequirePermission("contracts", "create"))
	contractRoutes.HandleFunc("", contractHandler.CreateContract).Methods("POST")

	contractRoutes.Use(authMiddleware.RequirePermission("contracts", "update"))
	contractRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.UpdateContract).Methods("PUT")

	contractRoutes.Use(authMiddleware.RequirePermission("contracts", "delete"))
	contractRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.DeleteContract).Methods("DELETE")

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
	// Ensure port doesn't have colons or invalid characters
	if len(port) == 0 || port[0] == ':' {
		port = "8080"
	}
	
	log.Printf("Starting server on port %s", port)
	log.Printf("Admin interface: http://localhost:%s", port)
	log.Printf("Health endpoint: http://localhost:%s/health (rate limited: 10/min)", port)
	log.Printf("Login endpoint: http://localhost:%s/auth/login (rate limited: 5/min)", port)
	log.Printf("Default admin credentials: admin / SenseGuard2025!")
	log.Printf("Default viewer credentials: viewer / Viewer2025!")
	
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
