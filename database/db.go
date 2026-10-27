// Package database manages the PostgreSQL connection lifecycle, GORM ORM configuration,
// schema auto-migrations, and table hardening for the Secure Token Allocation Backend.
package database

import (
	"log"
	"os"

	"token-alloc-backend/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB is the globally shared GORM database handle used across the entire backend.
//
// Interactions:
// - Exported and consumed directly by all HTTP request handlers in `token-alloc-backend/handlers`
//   for executing transactional queries, CRUD operations, atomic counters, and audit log inserts.
// - Initialized and populated once at server startup by InitDB().
var DB *gorm.DB

// InitDB initializes the PostgreSQL connection pool, configures driver settings for
// connection poolers, and performs database schema migrations.
//
// Working:
// 1. Connection Resolution:
//    Reads the `DATABASE_URL` environment variable. If unset, it falls back to the local
//    development connection string: "postgres://token_user:token_password_123@localhost:5432/token_db?sslmode=disable".
// 2. GORM Session & Driver Configuration:
//    Establishes a connection via GORM using postgres.New().
//    - Sets `PreferSimpleProtocol: true`: Disables prepared statement caching at the PostgreSQL driver level.
//      This is mandatory for cloud database poolers such as Supabase / PgBouncer operating in transaction mode,
//      preventing "prepared statement does not exist" errors.
//    - Sets `PrepareStmt: false`: Prevents GORM from retaining prepared statements in memory.
// 3. Connectivity Verification:
//    Terminates the application with log.Fatalf if the database cannot be reached.
// 4. Automated Schema Migration:
//    Invokes DB.AutoMigrate() on all domain models:
//    - models.Allocation: Daily token allocation session registry.
//    - models.FormField: Dynamic form inputs defined per allocation.
//    - models.RequestItem: End-user queue tickets with encrypted PII.
//    - models.Admin: Staff credentials, roles, and session invalidation counters.
//    - models.AuditLogItem: Immutable security and administrative action audit trail.
// 5. Schema Hardening (Backward Compatibility & Upgrades):
//    Executes raw idempotent `ALTER TABLE admins ADD COLUMN IF NOT EXISTS` statements to ensure
//    the `admins` table possesses `session_version`, `role`, `created_at`, and `updated_at` columns,
//    safeguarding migrations without requiring external migration tooling.
//
// Interactions:
// - Called synchronously by main() in main.go before starting the Gin web server.
// - Interacts with `models` package structs to define database tables, foreign keys, and indexes.
// - Populates the global `DB` variable used by handlers for queries, transactions, and mutations.
func InitDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://token_user:token_password_123@localhost:5432/token_db?sslmode=disable"
	}

	var err error
	DB, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // Disables prepared statement caching for Supabase pooler
	}), &gorm.Config{
		PrepareStmt: false,
	})
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL database: %v", err)
	}

	log.Println("Connected to PostgreSQL database successfully.")

	// AutoMigrate database models and ensure columns exist
	DB.AutoMigrate(&models.Allocation{}, &models.FormField{}, &models.RequestItem{}, &models.Admin{}, &models.AuditLogItem{})
	DB.Exec("ALTER TABLE admins ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 1;")
	DB.Exec("ALTER TABLE admins ADD COLUMN IF NOT EXISTS role VARCHAR(32) DEFAULT 'ADMIN';")
	DB.Exec("ALTER TABLE admins ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();")
	DB.Exec("ALTER TABLE admins ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();")
}

