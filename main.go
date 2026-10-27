// Package main serves as the primary entry point for the Secure Token Allocation Backend application.
// It initializes database connections, seeds mandatory administrative accounts,
// configures the Gin HTTP router with public and protected administrative endpoints,
// and starts the HTTP server listener.
package main

import (
	"log"
	"net/http"
	"os"

	"token-alloc-backend/database"
	"token-alloc-backend/handlers"

	"github.com/gin-gonic/gin"
)

// main is the application entry point.
//
// Working:
// 1. Database Initialization:
//    Calls database.InitDB() to establish a connection pool with PostgreSQL, execute
//    auto-migrations for all domain entities, and ensure required schema columns exist.
// 2. Default Administrator Seeding:
//    Invokes handlers.InitDefaultAdmin() to verify that a SUPER_ADMIN account exists
//    in the database, automatically creating one from environment variables if not present.
// 3. Router Initialization:
//    Initializes the Gin engine using gin.Default() (includes default Logger and Recovery middlewares).
// 4. Health Check Endpoint:
//    Exposes GET /api/health returning HTTP 200 {"status": "ok"} for load balancer or container uptime checks.
// 5. Public Route Group (/api/public):
//    Mounts unauthenticated endpoints used by public kiosks and end-user devices:
//    - GET /allocations/today: Retrieves active token sessions for today (handlers.GetTodayAllocations).
//    - GET /allocations/stream: SSE stream broadcasting live allocation updates (handlers.StreamPublicAllocations).
//    - GET /allocations/:id: Fetches single allocation session metadata with dynamic form fields (handlers.GetAllocationByID).
//    - POST /allocations/:id/requests: Submits encrypted token request into queue (handlers.SubmitTokenRequest).
//    - GET /requests/:id/status: Checks ticket status with PII masking or QR auth (handlers.GetRequestStatus).
//    - GET /requests/:id/stream: SSE stream for real-time ticket progress updates (handlers.StreamRequestStatus).
//    - POST /requests/:id/cancel: Allows users to cancel their own pending tickets (handlers.CancelOwnRequest).
//    - GET /requests/:id/qr-sig: Issues backend HMAC-SHA256 signature for verification QR code (handlers.GetQRSignature).
// 6. Administrative Route Group (/api/admin):
//    - Public Admin Route: POST /auth/login handles authentication and issues HMAC cookies (handlers.AdminLogin).
//    - Protected Admin Group: Uses handlers.AdminAuthMiddleware() to enforce strict 12-hour signed cookie authentication.
//      * GET /me: Current admin identity (handlers.GetAdminProfile).
//      * POST /auth/logout: Clears session cookie (handlers.AdminLogout).
//      * POST /change-credentials: Updates credentials and invalidates concurrent sessions (handlers.ChangeAdminCredentials).
//      * Allocation Operations: GET /allocations, POST /allocations, PATCH /allocations/:id, DELETE /allocations/:id/destroy.
//      * Request Lifecycle Operations: GET /requests, POST /requests/:id/accept, POST /requests/:id/reject,
//        POST /requests/:id/hold, POST /requests/:id/serve.
//      * Dashboard & Observability: GET /dashboard/stats, GET /dashboard/stream (SSE), GET /audit-logs.
//    - Super Admin Restricted Group: Uses handlers.SuperAdminMiddleware() in addition to AdminAuthMiddleware():
//      * GET /users, POST /users, DELETE /users/:id: Sub-admin account management.
//      * GET /allocations/:id/export: Exports session requests to Excel XLSX with decrypted form data.
// 7. Server Listener:
//    Reads PORT environment variable (defaulting to 8080) and launches the HTTP server listening on 0.0.0.0:PORT.
//
// Interactions:
// - Calls database.InitDB() to prepare database connectivity and tables before serving traffic.
// - Calls handlers.InitDefaultAdmin() to ensure authentication data integrity.
// - Wires all handler functions from token-alloc-backend/handlers into the Gin HTTP routing tree.
func main() {
	database.InitDB()
	handlers.InitDefaultAdmin()

	r := gin.Default()

	// Global CORS & preflight middleware
	r.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Origin")
			c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
			c.Writer.Header().Add("Vary", "Origin")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// Health check
	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Public API Endpoints
	pub := r.Group("/api/public")
	{
		pub.GET("/allocations/today", handlers.GetTodayAllocations)
		pub.GET("/allocations/stream", handlers.StreamPublicAllocations)
		pub.GET("/allocations/:id", handlers.GetAllocationByID)
		pub.POST("/allocations/:id/requests", handlers.SubmitTokenRequest)
		pub.GET("/requests/:id/status", handlers.GetRequestStatus)
		pub.GET("/requests/:id/stream", handlers.StreamRequestStatus)
		pub.POST("/requests/:id/cancel", handlers.CancelOwnRequest)
		pub.GET("/requests/:id/qr-sig", handlers.GetQRSignature)
	}

	// Admin API Endpoints
	adm := r.Group("/api/admin")
	{
		adm.POST("/auth/login", handlers.AdminLogin)

		// Protected Admin Routes requiring 12-Hour Cookie Authentication
		protected := adm.Group("")
		protected.Use(handlers.AdminAuthMiddleware())
		{
			protected.GET("/me", handlers.GetAdminProfile)
			protected.POST("/auth/logout", handlers.AdminLogout)
			protected.POST("/change-credentials", handlers.ChangeAdminCredentials)

			protected.GET("/allocations", handlers.GetAdminAllocations)
			protected.POST("/allocations", handlers.CreateAllocation)
			protected.PATCH("/allocations/:id", handlers.UpdateAllocationStatus)
			protected.DELETE("/allocations/:id/destroy", handlers.DestroyAllocation)

			protected.GET("/requests", handlers.GetAdminRequests)
			protected.POST("/requests/:id/accept", handlers.AcceptRequest)
			protected.POST("/requests/:id/reject", handlers.RejectRequest)
			protected.POST("/requests/:id/hold", handlers.HoldRequest)
			protected.POST("/requests/:id/serve", handlers.ServeRequest)

			protected.GET("/dashboard/stats", handlers.GetDashboardStats)
			protected.GET("/dashboard/stream", handlers.StreamAdminDashboard)
			protected.GET("/audit-logs", handlers.GetAuditLogs)

			// Super Admin Only Routes
			superOnly := protected.Group("")
			superOnly.Use(handlers.SuperAdminMiddleware())
			{
				superOnly.GET("/users", handlers.GetAllAdmins)
				superOnly.POST("/users", handlers.CreateSubAdmin)
				superOnly.DELETE("/users/:id", handlers.DeleteSubAdmin)
				superOnly.GET("/allocations/:id/export", handlers.ExportAllocationCSV)
			}
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // fallback for local development
	}

	log.Printf("Starting server on port %s...", port)
	if err := r.Run("0.0.0.0:" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
