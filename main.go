package main

import (
	"log"
	"net/http"
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
	serviceTierHandler := handlers.NewServiceTierHandler(database)
	diagnosticsHandler := handlers.NewDiagnosticsHandler(database)
	rateLimitHandler := handlers.NewRateLimitHandler(database)

	// Setup router
	r := mux.NewRouter()

	// Global middleware chain - order matters!
	r.Use(authMiddleware.CORS)           // 1. CORS first
	r.Use(middleware.Logger)             // 2. Request logging

	// Public routes (no authentication required)
	r.HandleFunc("/health", healthHandler.GetHealth).Methods("GET")
	r.HandleFunc("/auth/login", authHandler.Login).Methods("POST")

	// Protected routes (authentication required)
	authRoutes := r.PathPrefix("/auth").Subrouter()
	authRoutes.Use(authMiddleware.RequireAuth)
	authRoutes.HandleFunc("/profile", authHandler.GetCurrentUserProfile).Methods("GET")
	authRoutes.HandleFunc("/profile", authHandler.UpdateCurrentUserProfile).Methods("PUT")
	authRoutes.HandleFunc("/logout", authHandler.Logout).Methods("POST")
	authRoutes.HandleFunc("/change-password", authHandler.ChangePassword).Methods("POST")

	// Admin-only authentication routes
	adminAuthRoutes := r.PathPrefix("/auth").Subrouter()
	adminAuthRoutes.Use(authMiddleware.RequireAuth)

	// Password management routes (require users update permission)
	adminPasswordRoutes := r.PathPrefix("/auth").Subrouter()
	adminPasswordRoutes.Use(authMiddleware.RequireAuth)
	adminPasswordRoutes.Use(authMiddleware.RequirePermission("users", "update"))
	adminPasswordRoutes.HandleFunc("/users/{id:[0-9]+}/reset-password", authHandler.AdminResetPassword).Methods("POST")
	adminPasswordRoutes.HandleFunc("/users/{id:[0-9]+}/generate-password", authHandler.AdminGeneratePassword).Methods("POST")

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

	// User unlock route
	userUnlockRoutes := adminAuthRoutes.PathPrefix("/users").Subrouter()
	userUnlockRoutes.Use(authMiddleware.RequirePermission("users", "update"))
	userUnlockRoutes.HandleFunc("/{id:[0-9]+}/unlock", authHandler.UnlockUser).Methods("POST")

	// FIXED: Roles routes - Apply RequireAuth first, then permission check
	rolesRoutes := r.PathPrefix("/auth/roles").Subrouter()
	rolesRoutes.Use(authMiddleware.RequireAuth)  // CRITICAL: This was missing for standalone /auth/roles
	rolesRoutes.Use(authMiddleware.RequirePermission("roles", "read"))
	rolesRoutes.HandleFunc("", authHandler.GetRoles).Methods("GET")
	rolesRoutes.HandleFunc("/{id:[0-9]+}", authHandler.GetRole).Methods("GET")
	rolesRoutes.HandleFunc("/{id:[0-9]+}/users", authHandler.GetRoleUsers).Methods("GET")

	// Role creation routes
	roleCreateRoutes := r.PathPrefix("/auth/roles").Subrouter()
	roleCreateRoutes.Use(authMiddleware.RequireAuth)
	roleCreateRoutes.Use(authMiddleware.RequirePermission("roles", "create"))
	roleCreateRoutes.HandleFunc("", authHandler.CreateRole).Methods("POST")

	// Role update routes
	roleUpdateRoutes := r.PathPrefix("/auth/roles").Subrouter()
	roleUpdateRoutes.Use(authMiddleware.RequireAuth)
	roleUpdateRoutes.Use(authMiddleware.RequirePermission("roles", "update"))
	roleUpdateRoutes.HandleFunc("/{id:[0-9]+}", authHandler.UpdateRole).Methods("PUT")

	// Role delete routes
	roleDeleteRoutes := r.PathPrefix("/auth/roles").Subrouter()
	roleDeleteRoutes.Use(authMiddleware.RequireAuth)
	roleDeleteRoutes.Use(authMiddleware.RequirePermission("roles", "delete"))
	roleDeleteRoutes.HandleFunc("/{id:[0-9]+}", authHandler.DeleteRole).Methods("DELETE")
	roleDeleteRoutes.HandleFunc("/{id:[0-9]+}/deactivate", authHandler.DeactivateRole).Methods("POST")

	// Role usage and management routes
	roleManagementRoutes := r.PathPrefix("/auth/roles").Subrouter()
	roleManagementRoutes.Use(authMiddleware.RequireAuth)
	roleManagementRoutes.Use(authMiddleware.RequirePermission("roles", "read"))
	roleManagementRoutes.HandleFunc("/{id:[0-9]+}/usage", authHandler.GetRoleUsage).Methods("GET")
	roleManagementRoutes.HandleFunc("/{id:[0-9]+}/reassign", authHandler.ReassignRoleUsers).Methods("POST")

	// API Key management routes
	apiKeyRoutes := r.PathPrefix("/auth/api-keys").Subrouter()
	apiKeyRoutes.Use(authMiddleware.RequireAuth)

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
	apiKeyDeleteRoutes.HandleFunc("/{id:[0-9]+}", authHandler.PermanentlyDeleteAPIKey).Methods("DELETE")

	// Optional: Add deactivate route if you want both options
	apiKeyDeactivateRoutes := apiKeyRoutes.PathPrefix("").Subrouter()
	apiKeyDeactivateRoutes.Use(authMiddleware.RequirePermission("api_keys", "update"))
	apiKeyDeactivateRoutes.HandleFunc("/{id:[0-9]+}/deactivate", authHandler.DeactivateAPIKey).Methods("POST")

	// Customer routes - with proper rate limiting for API keys
	customerRoutes := r.PathPrefix("/customers").Subrouter()
	customerRoutes.Use(middleware.RateLimit(100, time.Hour))
	customerRoutes.Use(authMiddleware.RequirePermission("customers", "read"))
	customerRoutes.Use(authMiddleware.LogAPIUsage)
	customerRoutes.HandleFunc("", customerHandler.GetCustomers).Methods("GET")
	customerRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.GetCustomer).Methods("GET")
	customerRoutes.HandleFunc("/{id:[0-9]+}/contracts", customerHandler.GetCustomerWithContracts).Methods("GET")

	// Customer create routes
	customerCreateRoutes := r.PathPrefix("/customers").Subrouter()
	customerCreateRoutes.Use(middleware.RateLimit(10, time.Hour))
	customerCreateRoutes.Use(authMiddleware.RequirePermission("customers", "create"))
	customerCreateRoutes.Use(authMiddleware.LogAPIUsage)
	customerCreateRoutes.HandleFunc("", customerHandler.CreateCustomer).Methods("POST")

	// Customer update routes
	customerUpdateRoutes := r.PathPrefix("/customers").Subrouter()
	customerUpdateRoutes.Use(middleware.RateLimit(50, time.Hour))
	customerUpdateRoutes.Use(authMiddleware.RequirePermission("customers", "update"))
	customerUpdateRoutes.Use(authMiddleware.LogAPIUsage)
	customerUpdateRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.UpdateCustomer).Methods("PUT")

	// Customer delete routes
	customerDeleteRoutes := r.PathPrefix("/customers").Subrouter()
	customerDeleteRoutes.Use(middleware.RateLimit(5, time.Hour))
	customerDeleteRoutes.Use(authMiddleware.RequirePermission("customers", "delete"))
	customerDeleteRoutes.Use(authMiddleware.LogAPIUsage)
	customerDeleteRoutes.HandleFunc("/{id:[0-9]+}", customerHandler.DeleteCustomer).Methods("DELETE")

	// Contract routes - with proper rate limiting for API keys
	contractRoutes := r.PathPrefix("/contracts").Subrouter()
	contractRoutes.Use(middleware.RateLimit(100, time.Hour))
	contractRoutes.Use(authMiddleware.RequirePermission("contracts", "read"))
	contractRoutes.Use(authMiddleware.LogAPIUsage)
	contractRoutes.HandleFunc("", contractHandler.GetContracts).Methods("GET")
	contractRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.GetContract).Methods("GET")

	// Contract create routes
	contractCreateRoutes := r.PathPrefix("/contracts").Subrouter()
	contractCreateRoutes.Use(middleware.RateLimit(10, time.Hour))
	contractCreateRoutes.Use(authMiddleware.RequirePermission("contracts", "create"))
	contractCreateRoutes.Use(authMiddleware.LogAPIUsage)
	contractCreateRoutes.HandleFunc("", contractHandler.CreateContract).Methods("POST")

	// Contract update routes
	contractUpdateRoutes := r.PathPrefix("/contracts").Subrouter()
	contractUpdateRoutes.Use(middleware.RateLimit(50, time.Hour))
	contractUpdateRoutes.Use(authMiddleware.RequirePermission("contracts", "update"))
	contractUpdateRoutes.Use(authMiddleware.LogAPIUsage)
	contractUpdateRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.UpdateContract).Methods("PUT")

	// Contract delete routes
	contractDeleteRoutes := r.PathPrefix("/contracts").Subrouter()
	contractDeleteRoutes.Use(middleware.RateLimit(5, time.Hour))
	contractDeleteRoutes.Use(authMiddleware.RequirePermission("contracts", "delete"))
	contractDeleteRoutes.Use(authMiddleware.LogAPIUsage)
	contractDeleteRoutes.HandleFunc("/{id:[0-9]+}", contractHandler.DeleteContract).Methods("DELETE")

	// Service Tier routes - with proper rate limiting
	serviceTierRoutes := r.PathPrefix("/service-tiers").Subrouter()
	serviceTierRoutes.Use(middleware.RateLimit(100, time.Hour))
	serviceTierRoutes.Use(authMiddleware.RequirePermission("service_tiers", "read"))
	serviceTierRoutes.Use(authMiddleware.LogAPIUsage)
	serviceTierRoutes.HandleFunc("", serviceTierHandler.GetServiceTiers).Methods("GET")
	serviceTierRoutes.HandleFunc("/{id:[0-9]+}", serviceTierHandler.GetServiceTier).Methods("GET")

	// Service tier create routes
	serviceTierCreateRoutes := r.PathPrefix("/service-tiers").Subrouter()
	serviceTierCreateRoutes.Use(middleware.RateLimit(10, time.Hour))
	serviceTierCreateRoutes.Use(authMiddleware.RequirePermission("service_tiers", "create"))
	serviceTierCreateRoutes.Use(authMiddleware.LogAPIUsage)
	serviceTierCreateRoutes.HandleFunc("", serviceTierHandler.CreateServiceTier).Methods("POST")

	// Service tier update routes
	serviceTierUpdateRoutes := r.PathPrefix("/service-tiers").Subrouter()
	serviceTierUpdateRoutes.Use(middleware.RateLimit(50, time.Hour))
	serviceTierUpdateRoutes.Use(authMiddleware.RequirePermission("service_tiers", "update"))
	serviceTierUpdateRoutes.Use(authMiddleware.LogAPIUsage)
	serviceTierUpdateRoutes.HandleFunc("/{id:[0-9]+}", serviceTierHandler.UpdateServiceTier).Methods("PUT")

	// Service tier delete routes
	serviceTierDeleteRoutes := r.PathPrefix("/service-tiers").Subrouter()
	serviceTierDeleteRoutes.Use(middleware.RateLimit(5, time.Hour))
	serviceTierDeleteRoutes.Use(authMiddleware.RequirePermission("service_tiers", "delete"))
	serviceTierDeleteRoutes.Use(authMiddleware.LogAPIUsage)
	serviceTierDeleteRoutes.HandleFunc("/{id:[0-9]+}", serviceTierHandler.DeleteServiceTier).Methods("DELETE")

	// Diagnostics routes (admin only) - with strict rate limiting
	diagnosticsRoutes := r.PathPrefix("/diagnostics").Subrouter()
	diagnosticsRoutes.Use(middleware.RateLimit(20, time.Hour))
	diagnosticsRoutes.Use(authMiddleware.RequirePermission("diagnostics", "read"))
	diagnosticsRoutes.HandleFunc("/db-status", diagnosticsHandler.GetDatabaseStatus).Methods("GET")
	diagnosticsRoutes.HandleFunc("/system-info", diagnosticsHandler.GetSystemInfo).Methods("GET")

	// Rate Limit Monitoring Routes (admin only)
	rateLimitRoutes := r.PathPrefix("/admin/rate-limits").Subrouter()
	rateLimitRoutes.Use(middleware.RateLimit(50, time.Hour))
	rateLimitRoutes.Use(authMiddleware.RequirePermission("api_keys", "read"))
	rateLimitRoutes.HandleFunc("/status", rateLimitHandler.GetAllAPIKeyRateLimitStatus).Methods("GET")
	rateLimitRoutes.HandleFunc("/metrics", rateLimitHandler.GetRateLimitingMetrics).Methods("GET")
	rateLimitRoutes.HandleFunc("/{id:[0-9]+}", rateLimitHandler.GetAPIKeyRateLimitStatus).Methods("GET")

	// Rate limit admin actions (admin only)
	rateLimitAdminRoutes := r.PathPrefix("/admin/rate-limits").Subrouter()
	rateLimitAdminRoutes.Use(middleware.RateLimit(10, time.Hour))
	rateLimitAdminRoutes.Use(authMiddleware.RequireRole("admin"))
	rateLimitAdminRoutes.HandleFunc("/{id:[0-9]+}/reset", rateLimitHandler.ResetAPIKeyRateLimit).Methods("POST")

	// Start server
	port := cfg.Server.Port
	if port == "" {
		port = "8080"
	}

	// Ensure port doesn't have extra characters
	if port[0] == ':' {
		port = port[1:]
	}

	log.Printf("🚀 Starting Sense Security API Server on port :%s", port)
	log.Printf("📡 API Base URL: http://localhost:%s", port)
	log.Printf("🔐 Default admin credentials: admin / SenseGuard2025!")
	log.Printf("👀 Default viewer credentials: viewer / Viewer2025!")
	log.Printf("⚡ Rate limiting: ENABLED")
	log.Printf("🛡️  CORS: ENABLED")
	log.Printf("📊 API usage logging: ENABLED")
	log.Printf("💾 Database: Connected")
	log.Printf("🔑 JWT Auth: Enabled")
	log.Printf("📋 Service Tiers: Enabled")
	log.Printf("🤝 Contract-Customer Mapping: Enabled")
	log.Println("────────────────────────────────────────")
	log.Println("✅ API Server ready to accept connections")

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("❌ Server failed to start: %v", err)
	}
}
