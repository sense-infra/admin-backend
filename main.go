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
	healthHandler := handlers.NewHealthHandler(database)
	authHandler := handlers.NewAuthHandler(authService)
	customerHandler := handlers.NewCustomerHandler(database)
	contractHandler := handlers.NewContractHandler(database)
	diagnosticsHandler := handlers.NewDiagnosticsHandler(database)
	rateLimitHandler := handlers.NewRateLimitHandler(database)

	// Setup router
	r := mux.NewRouter()

	// Global middleware chain - order matters!
	r.Use(authMiddleware.CORS)           // 1. CORS first
	r.Use(middleware.Logger)             // 2. Request logging
	// Note: LogAPIUsage will be applied to protected routes only

	// Handle root path specifically for admin interface
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// Serve admin interface
			http.ServeFile(w, r, "./web/admin.html")
		}
	}).Methods("GET")

	// Public routes (no authentication required)
	// Note: No "/api/v1" prefix since k8s adds it
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
	adminAuthRoutes.Use(authMiddleware.RequireAuth)
	
	// User management routes
	userRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userRoutes.Use(authMiddleware.RequirePermission("users", "read"))
	userRoutes.HandleFunc("", authHandler.GetUsers).Methods("GET")
	userRoutes.HandleFunc("/{id:[0-9]+}", authHandler.GetUser).Methods("GET")
	
	// User creation route
	userCreateRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userCreateRoutes.Use(authMiddleware.RequirePermission("users", "create"))
	userCreateRoutes.HandleFunc("", authHandler.CreateUser).Methods("POST")
	
	// User update route
	userUpdateRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userUpdateRoutes.Use(authMiddleware.RequirePermission("users", "update"))
	userUpdateRoutes.HandleFunc("/{id:[0-9]+}", authHandler.UpdateUser).Methods("PUT")
	
	// User delete route
	userDeleteRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userDeleteRoutes.Use(authMiddleware.RequirePermission("users", "delete"))
	userDeleteRoutes.HandleFunc("/{id:[0-9]+}", authHandler.DeleteUser).Methods("DELETE")

	// Permanent delete route (separate endpoint)
	userPermanentDeleteRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userPermanentDeleteRoutes.Use(authMiddleware.RequirePermission("users", "delete"))
	userPermanentDeleteRoutes.HandleFunc("/{id:[0-9]+}/permanent", authHandler.PermanentlyDeleteUser).Methods("DELETE")

	// Add this with your other user routes
	userUnlockRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userUnlockRoutes.Use(authMiddleware.RequirePermission("users", "update"))
	userUnlockRoutes.HandleFunc("/{id:[0-9]+}/unlock", authHandler.UnlockUser).Methods("POST")

	// Roles route
	rolesRoutes := adminAuthRoutes.PathPrefix("/roles").Subrouter()
	rolesRoutes.Use(authMiddleware.RequirePermission("users", "read"))
	rolesRoutes.HandleFunc("", authHandler.GetRoles).Methods("GET")

	// API Key management routes
	apiKeyRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
	
	// API Key read routes
	apiKeyReadRoutes := apiKeyRoutes.PathPrefix("").Subrouter()
	apiKeyReadRoutes.Use(authMiddleware.RequirePermission("api_keys", "read"))
	apiKeyReadRoutes.HandleFunc("", authHandler.GetAPIKeys).Methods("GET")
	apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}", authHandler.GetAPIKey).Methods("GET")
	apiKeyReadRoutes.HandleFunc("/{id:[0-9]+}/usage", authHandler.GetAPIKeyUsage).Methods("GET")

	// API Key create routes
	apiKeyCreateRoutes := apiKeyRoutes.PathPrefix("").Subrouter()
	apiKeyCreateRoutes.Use(authMiddleware.RequirePermission("api_keys", "create"))
	apiKeyCreateRoutes.HandleFunc("", authHandler.CreateAPIKey).Methods("POST")

	// API Key update routes
	apiKeyUpdateRoutes := apiKeyRoutes.PathPrefix("").Subrouter()
	apiKeyUpdateRoutes.Use(authMiddleware.RequirePermission("api_keys", "update"))
	apiKeyUpdateRoutes.HandleFunc("/{id:[0-9]+}", authHandler.UpdateAPIKey).Methods("PUT")

	// API Key delete routes
	apiKeyDeleteRoutes := apiKeyRoutes.PathPrefix("").Subrouter()
	apiKeyDeleteRoutes.Use(authMiddleware.RequirePermission("api_keys", "delete"))
	apiKeyDeleteRoutes.HandleFunc("/{id:[0-9]+}", authHandler.DeleteAPIKey).Methods("DELETE")

	// Customer routes - with proper rate limiting for API keys
	customerRoutes := r.PathPrefix("/customers").Subrouter()
	customerRoutes.Use(middleware.RateLimit(100, time.Hour))  // General rate limit: 100 req/hour for IP-based
	customerRoutes.Use(authMiddleware.RequirePermission("customers", "read"))
	customerRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	customerRoutes.HandleFunc("", customerHandler.GetCustomers).Methods("GET")
	customerRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.GetCustomer).Methods("GET")

	// Customer create routes
	customerCreateRoutes := r.PathPrefix("/customers").Subrouter()
	customerCreateRoutes.Use(middleware.RateLimit(10, time.Hour))  // Stricter limit for creates
	customerCreateRoutes.Use(authMiddleware.RequirePermission("customers", "create"))
	customerCreateRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	customerCreateRoutes.HandleFunc("", customerHandler.CreateCustomer).Methods("POST")

	// Customer update routes
	customerUpdateRoutes := r.PathPrefix("/customers").Subrouter()
	customerUpdateRoutes.Use(middleware.RateLimit(50, time.Hour))  // Moderate limit for updates
	customerUpdateRoutes.Use(authMiddleware.RequirePermission("customers", "update"))
	customerUpdateRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	customerUpdateRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.UpdateCustomer).Methods("PUT")

	// Customer delete routes
	customerDeleteRoutes := r.PathPrefix("/customers").Subrouter()
	customerDeleteRoutes.Use(middleware.RateLimit(5, time.Hour))   // Very strict limit for deletes
	customerDeleteRoutes.Use(authMiddleware.RequirePermission("customers", "delete"))
	customerDeleteRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	customerDeleteRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.DeleteCustomer).Methods("DELETE")

	// Contract routes - with proper rate limiting for API keys
	contractRoutes := r.PathPrefix("/contracts").Subrouter()
	contractRoutes.Use(middleware.RateLimit(100, time.Hour))  // General rate limit: 100 req/hour for IP-based
	contractRoutes.Use(authMiddleware.RequirePermission("contracts", "read"))
	contractRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	contractRoutes.HandleFunc("", contractHandler.GetContracts).Methods("GET")
	contractRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.GetContract).Methods("GET")

	// Contract create routes
	contractCreateRoutes := r.PathPrefix("/contracts").Subrouter()
	contractCreateRoutes.Use(middleware.RateLimit(10, time.Hour))  // Stricter limit for creates
	contractCreateRoutes.Use(authMiddleware.RequirePermission("contracts", "create"))
	contractCreateRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	contractCreateRoutes.HandleFunc("", contractHandler.CreateContract).Methods("POST")

	// Contract update routes
	contractUpdateRoutes := r.PathPrefix("/contracts").Subrouter()
	contractUpdateRoutes.Use(middleware.RateLimit(50, time.Hour))  // Moderate limit for updates
	contractUpdateRoutes.Use(authMiddleware.RequirePermission("contracts", "update"))
	contractUpdateRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	contractUpdateRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.UpdateContract).Methods("PUT")

	// Contract delete routes
	contractDeleteRoutes := r.PathPrefix("/contracts").Subrouter()
	contractDeleteRoutes.Use(middleware.RateLimit(5, time.Hour))   // Very strict limit for deletes
	contractDeleteRoutes.Use(authMiddleware.RequirePermission("contracts", "delete"))
	contractDeleteRoutes.Use(authMiddleware.LogAPIUsage)  // Log API usage AFTER authentication
	contractDeleteRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.DeleteContract).Methods("DELETE")

	// Diagnostics routes (admin only) - with strict rate limiting
	diagnosticsRoutes := r.PathPrefix("/diagnostics").Subrouter()
	diagnosticsRoutes.Use(middleware.RateLimit(20, time.Hour))     // Very limited for diagnostics
	diagnosticsRoutes.Use(authMiddleware.RequireRole("admin"))
	diagnosticsRoutes.HandleFunc("/db-status", diagnosticsHandler.GetDatabaseStatus).Methods("GET")
	diagnosticsRoutes.HandleFunc("/system-info", diagnosticsHandler.GetSystemInfo).Methods("GET")

	// Rate Limit Monitoring Routes (admin only)
	rateLimitRoutes := r.PathPrefix("/admin/rate-limits").Subrouter()
	rateLimitRoutes.Use(middleware.RateLimit(50, time.Hour))       // Moderate limit for monitoring
	rateLimitRoutes.Use(authMiddleware.RequirePermission("api_keys", "read"))
	rateLimitRoutes.HandleFunc("/status", rateLimitHandler.GetAllAPIKeyRateLimitStatus).Methods("GET")
	rateLimitRoutes.HandleFunc("/metrics", rateLimitHandler.GetRateLimitingMetrics).Methods("GET")
	rateLimitRoutes.HandleFunc("/{id:[0-9]+}", rateLimitHandler.GetAPIKeyRateLimitStatus).Methods("GET")
	
	// Rate limit admin actions (admin only)
	rateLimitAdminRoutes := r.PathPrefix("/admin/rate-limits").Subrouter()
	rateLimitAdminRoutes.Use(middleware.RateLimit(10, time.Hour))   // Very strict for admin actions
	rateLimitAdminRoutes.Use(authMiddleware.RequireRole("admin"))
	rateLimitAdminRoutes.HandleFunc("/{id:[0-9]+}/reset", rateLimitHandler.ResetAPIKeyRateLimit).Methods("POST")

	// Serve static files (web interface)
	webDir := "./web/"
	if _, err := os.Stat(webDir); os.IsNotExist(err) {
		log.Println("Web directory not found, creating basic file server")
		r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("./"))))
	} else {
		r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir(webDir))))
	}

	// Start server
	port := cfg.Server.Port
	if port == "" {
		port = "8080" // Default port
	}
	
	// Ensure port doesn't have extra characters
	if port[0] == ':' {
		port = port[1:] // Remove leading colon if present
	}
	
	log.Printf("Starting server on :%s", port)
	log.Printf("Admin interface: http://localhost:%s", port)
	log.Printf("API endpoint: http://localhost:%s (no /api/v1 prefix - k8s adds it)", port)
	log.Printf("Default admin credentials: admin / SenseGuard2025!")
	log.Printf("Default viewer credentials: viewer / Viewer2025!")
	log.Printf("API Key rate limiting: ENABLED (per-key hourly limits)")
	log.Printf("IP-based rate limiting: ENABLED (varies by endpoint)")
	
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
