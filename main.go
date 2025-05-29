package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sense-security/api/config"
	"github.com/sense-security/api/db"
	"github.com/sense-security/api/handlers"
	"github.com/sense-security/api/middleware"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	database, err := db.Initialize(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Create router
	router := mux.NewRouter()

	// Apply middleware
	router.Use(middleware.Logger)
	router.Use(middleware.CORS)
	router.Use(middleware.ContentType)

	// Initialize handlers
	h := handlers.New(database)

	// Health check endpoint (no auth required)
	router.HandleFunc("/health", h.HealthCheck).Methods("GET")
	router.HandleFunc("/health/detailed", h.HealthCheckDetailed).Methods("GET")
	router.HandleFunc("/diagnostics/database", h.DatabaseDiagnostics).Methods("GET")
	router.HandleFunc("/ready", h.ReadinessCheck).Methods("GET")

	// API routes with authentication
	api := router.PathPrefix("/api").Subrouter()
	api.Use(middleware.APIKeyAuth(cfg.Auth.APIKeys))

	// Customer routes
	api.HandleFunc("/customers", h.ListCustomers).Methods("GET")
	api.HandleFunc("/customers", h.CreateCustomer).Methods("POST")
	api.HandleFunc("/customers/{id}", h.GetCustomer).Methods("GET")
	api.HandleFunc("/customers/{id}", h.UpdateCustomer).Methods("PUT")
	api.HandleFunc("/customers/{id}", h.DeleteCustomer).Methods("DELETE")

	// Contract routes
	api.HandleFunc("/contracts", h.ListContracts).Methods("GET")
	api.HandleFunc("/contracts", h.CreateContract).Methods("POST")
	api.HandleFunc("/contracts/{id}", h.GetContract).Methods("GET")
	api.HandleFunc("/contracts/{id}", h.UpdateContract).Methods("PUT")
	api.HandleFunc("/contracts/{id}", h.DeleteContract).Methods("DELETE")
	api.HandleFunc("/contracts/{id}/customers", h.ListContractCustomers).Methods("GET")
	api.HandleFunc("/contracts/{id}/customers/{customerId}", h.AddCustomerToContract).Methods("POST")
	api.HandleFunc("/contracts/{id}/customers/{customerId}", h.RemoveCustomerFromContract).Methods("DELETE")

	// Service Tier routes
	api.HandleFunc("/service-tiers", h.ListServiceTiers).Methods("GET")
	api.HandleFunc("/service-tiers", h.CreateServiceTier).Methods("POST")
	api.HandleFunc("/service-tiers/{id}", h.GetServiceTier).Methods("GET")
	api.HandleFunc("/service-tiers/{id}", h.UpdateServiceTier).Methods("PUT")
	api.HandleFunc("/service-tiers/{id}", h.DeleteServiceTier).Methods("DELETE")

	// Contract Service Tier assignment
	api.HandleFunc("/contracts/{id}/service-tier", h.AssignServiceTier).Methods("POST")
	api.HandleFunc("/contracts/{id}/service-tier/current", h.GetCurrentServiceTier).Methods("GET")

	// NVR routes
	api.HandleFunc("/nvr-profiles", h.ListNVRProfiles).Methods("GET")
	api.HandleFunc("/nvr-profiles", h.CreateNVRProfile).Methods("POST")
	api.HandleFunc("/nvr-profiles/{id}", h.GetNVRProfile).Methods("GET")
	api.HandleFunc("/nvr-profiles/{id}", h.UpdateNVRProfile).Methods("PUT")
	api.HandleFunc("/nvr-profiles/{id}", h.DeleteNVRProfile).Methods("DELETE")

	api.HandleFunc("/nvrs", h.ListNVRs).Methods("GET")
	api.HandleFunc("/nvrs", h.CreateNVR).Methods("POST")
	api.HandleFunc("/nvrs/{id}", h.GetNVR).Methods("GET")
	api.HandleFunc("/nvrs/{id}", h.UpdateNVR).Methods("PUT")
	api.HandleFunc("/nvrs/{id}", h.DeleteNVR).Methods("DELETE")

	// Camera routes
	api.HandleFunc("/cameras", h.ListCameras).Methods("GET")
	api.HandleFunc("/cameras", h.CreateCamera).Methods("POST")
	api.HandleFunc("/cameras/{id}", h.GetCamera).Methods("GET")
	api.HandleFunc("/cameras/{id}", h.UpdateCamera).Methods("PUT")
	api.HandleFunc("/cameras/{id}", h.DeleteCamera).Methods("DELETE")

	// Controller routes
	api.HandleFunc("/controllers", h.ListControllers).Methods("GET")
	api.HandleFunc("/controllers", h.CreateController).Methods("POST")
	api.HandleFunc("/controllers/{id}", h.GetController).Methods("GET")
	api.HandleFunc("/controllers/{id}", h.UpdateController).Methods("PUT")
	api.HandleFunc("/controllers/{id}", h.DeleteController).Methods("DELETE")

	// TPM Device routes
	api.HandleFunc("/tpm-devices", h.ListTPMDevices).Methods("GET")
	api.HandleFunc("/tpm-devices", h.CreateTPMDevice).Methods("POST")
	api.HandleFunc("/tpm-devices/{id}", h.GetTPMDevice).Methods("GET")
	api.HandleFunc("/tpm-devices/{id}", h.UpdateTPMDevice).Methods("PUT")
	api.HandleFunc("/tpm-devices/{id}", h.DeleteTPMDevice).Methods("DELETE")

	// VPN Config routes
	api.HandleFunc("/vpn-configs", h.ListVPNConfigs).Methods("GET")
	api.HandleFunc("/vpn-configs", h.CreateVPNConfig).Methods("POST")
	api.HandleFunc("/vpn-configs/{id}", h.GetVPNConfig).Methods("GET")
	api.HandleFunc("/vpn-configs/{id}", h.UpdateVPNConfig).Methods("PUT")
	api.HandleFunc("/vpn-configs/{id}", h.DeleteVPNConfig).Methods("DELETE")

	// RF Frequency routes
	api.HandleFunc("/rf-frequencies", h.ListRFFrequencies).Methods("GET")
	api.HandleFunc("/rf-frequencies", h.CreateRFFrequency).Methods("POST")
	api.HandleFunc("/rf-frequencies/{id}", h.GetRFFrequency).Methods("GET")
	api.HandleFunc("/rf-frequencies/{id}", h.UpdateRFFrequency).Methods("PUT")
	api.HandleFunc("/rf-frequencies/{id}", h.DeleteRFFrequency).Methods("DELETE")

	// Contract RF Monitoring routes
	api.HandleFunc("/contracts/{id}/rf-monitoring", h.ListContractRFMonitoring).Methods("GET")
	api.HandleFunc("/contracts/{id}/rf-monitoring", h.ConfigureRFMonitoring).Methods("POST")
	api.HandleFunc("/contracts/{id}/rf-monitoring/{frequencyId}", h.UpdateRFMonitoring).Methods("PUT")
	api.HandleFunc("/contracts/{id}/rf-monitoring/{frequencyId}", h.DeleteRFMonitoring).Methods("DELETE")

	// Mapping routes
	api.HandleFunc("/contracts/{id}/nvrs", h.ListContractNVRs).Methods("GET")
	api.HandleFunc("/contracts/{id}/nvrs/{nvrId}", h.AddNVRToContract).Methods("POST")
	api.HandleFunc("/contracts/{id}/nvrs/{nvrId}", h.RemoveNVRFromContract).Methods("DELETE")

	api.HandleFunc("/nvrs/{id}/cameras", h.ListNVRCameras).Methods("GET")
	api.HandleFunc("/nvrs/{id}/cameras/{cameraId}", h.AddCameraToNVR).Methods("POST")
	api.HandleFunc("/nvrs/{id}/cameras/{cameraId}", h.RemoveCameraFromNVR).Methods("DELETE")

	api.HandleFunc("/nvrs/{id}/controllers", h.ListNVRControllers).Methods("GET")
	api.HandleFunc("/nvrs/{id}/controllers/{controllerId}", h.AddControllerToNVR).Methods("POST")
	api.HandleFunc("/nvrs/{id}/controllers/{controllerId}", h.RemoveControllerFromNVR).Methods("DELETE")

	api.HandleFunc("/controllers/{id}/cameras", h.ListControllerCameras).Methods("GET")
	api.HandleFunc("/controllers/{id}/cameras/{cameraId}/support", h.AddCameraSupport).Methods("POST")
	api.HandleFunc("/controllers/{id}/cameras/{cameraId}/support", h.RemoveCameraSupport).Methods("DELETE")

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server shutdown complete")
}
