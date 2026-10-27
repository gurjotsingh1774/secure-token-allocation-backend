// Package models defines the core domain entities, relational schema mapping tags,
// and JSON serialization contracts for the Secure Token Allocation Backend.
package models

import (
	"time"
)

// Allocation represents a scheduled token allocation session (e.g., "Morning OPD Session", "Document Verification").
// It manages daily quotas, queue counters, operating hours, and custom dynamic form schemas.
//
// Working:
// - Serves as the parent entity for token requests and custom form field definitions.
// - Tracks the monotonic token sequence counter (`CurrentSequence`) incremented when requests are accepted.
// - Enforces session statuses:
//   * "ACTIVE": Accepting public submissions and processing queue.
//   * "PAUSED": Temporarily holds new user submissions while allowing admins to process existing queue.
//   * "CLOSED": Automatically or manually marked closed for the day.
//   * "COMPLETED": Session finalized by administration; no further actions accepted.
//
// Interactions:
// - Has a 1-to-Many relationship with `FormField` via foreign key `AllocationID`.
// - Referenced by `RequestItem.AllocationID` to bind user requests to specific sessions.
// - Managed by admin handlers (CreateAllocation, UpdateAllocationStatus, DestroyAllocation).
// - Queried by public handlers (GetTodayAllocations, GetAllocationByID, StreamPublicAllocations).
type Allocation struct {
	ID                     string      `gorm:"primaryKey" json:"id"`
	Date                   string      `json:"date"`                                      // Session date in YYYY-MM-DD format
	Name                   string      `json:"name"`                                      // Human-readable title of the allocation session
	Description            string      `json:"description"`                               // Detailed description or purpose of session
	OpeningTime            string      `json:"opening_time"`                              // Daily opening time (e.g., "09:00 AM")
	ClosingTime            string      `json:"closing_time"`                              // Daily closing time (e.g., "05:00 PM")
	MaxTokens              int         `json:"max_tokens,omitempty"`                      // Optional cap on maximum tokens issued per session
	AdditionalInstructions string      `json:"additional_instructions"`                   // Guidance shown to public users on ticket creation
	Status                 string      `json:"status"`                                    // ACTIVE, PAUSED, CLOSED, COMPLETED
	CurrentSequence        int         `json:"current_sequence"`                          // Monotonically increasing token counter for this session
	WaitingCount           int         `json:"waiting_count"`                             // Cached count of currently pending requests
	FormFields             []FormField `gorm:"foreignKey:AllocationID" json:"form_fields,omitempty"` // Dynamic custom fields for this session
	CreatedAt              time.Time   `json:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at"`
}

// FormField defines a dynamic, administrator-configurable input field required when users submit
// requests for a specific Allocation (e.g., "Full Name", "Aadhaar / ID Number", "Department").
//
// Working:
// - Enables zero-code customization of registration forms per allocation session.
// - Stored in the database with display ordering and required flags.
// - Serializes select dropdown choices in JSON within the `Options` column.
//
// Interactions:
// - Belongs to an `Allocation` through `AllocationID` (cascaded on allocation deletion).
// - Read by public frontend clients to dynamically render forms on kiosks or mobile screens.
// - Consumed during ExportAllocationCSV to generate dynamic columns for Excel exports.
type FormField struct {
	ID           string `gorm:"primaryKey" json:"id"`
	AllocationID string `json:"allocation_id"` // Foreign key referencing Allocation.ID
	FieldKey     string `json:"field_key"`     // Unique programmatic key used in submitted FormData JSON
	Label        string `json:"label"`         // User-facing label displayed in forms
	FieldType    string `json:"field_type"`    // Input type: "text", "number", "select", "email", etc.
	Required     bool   `json:"required"`      // Whether user must provide a value to submit
	Options      string `json:"options,omitempty"` // JSON-encoded array of options for select dropdowns
	DisplayOrder int    `json:"display_order"` // Sorting order for form rendering
}

// RequestItem represents an individual token request submitted by an end-user for an Allocation session.
//
// Working:
// - Captures user-submitted data, status lifecycle, queue positioning, and token number assignment.
// - Enforces data confidentiality: `FormData` is encrypted with AES-256-CFB at rest to protect
//   personally identifiable information (PII).
// - Status lifecycle:
//   * "PENDING": Request submitted; waiting in queue for administrative review.
//   * "ACCEPTED": Approved by admin; issued an official monotonic token number (`AssignedToken`).
//   * "HOLD": Temporarily placed on hold by counter staff.
//   * "SERVED": Completed service at the counter.
//   * "REJECTED": Denied by admin review.
//   * "CANCELLED": Cancelled by end-user before approval.
//
// Interactions:
// - Linked to `Allocation` via `AllocationID`.
// - Created by `handlers.SubmitTokenRequest` with AES encryption via `services.Encrypt`.
// - Decrypted and converted to `RequestItemDTO` via `handlers.toDTO` / `handlers.toAuthorizedDTO`.
// - Lifecycle state transitioned by admin actions (AcceptRequest, RejectRequest, HoldRequest, ServeRequest)
//   or user cancellation (CancelOwnRequest).
// - Tracked live in real-time via SSE streams (StreamRequestStatus).
type RequestItem struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	AllocationID   string    `json:"allocation_id"`             // Foreign key linking to Allocation.ID
	AllocationName string    `json:"allocation_name"`           // Denormalized allocation name for fast lookups
	Date           string    `json:"date"`                      // Date of session in YYYY-MM-DD
	UserSessionID  string    `json:"user_session_id"`           // Browser/device fingerprint preventing duplicate spam
	FormData       string    `json:"form_data"`                 // Encrypted AES-256-CFB Base64 JSON string holding user PII
	Status         string    `json:"status"`                    // PENDING, ACCEPTED, HOLD, REJECTED, CANCELLED, EXPIRED, SERVED
	AssignedToken  int       `json:"assigned_token,omitempty"`  // Official issued queue token number (set when ACCEPTED)
	QueuePosition  int       `json:"queue_position"`            // Initial sequence position at time of submission
	EstimatedWait  int       `json:"estimated_wait"`            // Computed wait time in minutes
	IdempotencyKey string    `json:"idempotency_key,omitempty"` // Client-generated key preventing accidental double submissions
	SubmittedAt    time.Time `json:"submitted_at"`
	AcceptedAt     time.Time `json:"accepted_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Admin represents an administrative user account authorized to manage sessions and counter queues.
//
// Working:
// - Supports Role-Based Access Control (RBAC):
//   * "SUPER_ADMIN": Complete authority; can create/delete sub-admins, export CSVs, destroy sessions.
//   * "ADMIN": Operational counter authority; can accept/reject/hold/serve tickets and create sessions.
// - Multi-Device Invalidation: The `SessionVersion` integer is embedded inside signed cookies.
//   When credentials change, `SessionVersion` increments, immediately revoking active cookies on other devices.
//
// Interactions:
// - Initialized or verified on boot by `handlers.InitDefaultAdmin`.
// - Authenticated via `handlers.AdminLogin`, which signs 12-hour session cookies.
// - Verified on protected routes by `handlers.AdminAuthMiddleware` and `handlers.SuperAdminMiddleware`.
// - Managed by Super Admins via `handlers.GetAllAdmins`, `handlers.CreateSubAdmin`, and `handlers.DeleteSubAdmin`.
type Admin struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	Username       string    `gorm:"uniqueIndex;not null" json:"username"`
	Password       string    `json:"-"`                                    // Secure bcrypt hash (never exposed in JSON)
	Role           string    `gorm:"not null;default:'ADMIN'" json:"role"` // "SUPER_ADMIN" or "ADMIN"
	SessionVersion int       `gorm:"not null;default:1" json:"session_version"` // Invalidation counter for active sessions
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AuditLogItem records an immutable security and operational audit trail entry for administrative actions.
//
// Working:
// - Captures administrative events (e.g. ALLOCATION_CREATED, SESSION_DESTROYED_FULL_PURGE).
// - Stores client IP address, timestamp, affected entity identifiers, and contextual JSON metadata.
//
// Interactions:
// - Created by administrative handlers (e.g., CreateAllocation, DestroyAllocation).
// - Queried by `handlers.GetAuditLogs` to populate the administrative audit trail UI.
type AuditLogItem struct {
	ID           string    `gorm:"primaryKey" json:"id"`
	Event        string    `json:"event"`                  // Event identifier (e.g., "ALLOCATION_CREATED", "SESSION_DESTROYED")
	AdminID      string    `json:"admin_id,omitempty"`     // Identifier of admin who initiated action (if authenticated)
	RequestID    string    `json:"request_id,omitempty"`   // Target request identifier (if action targeted a request)
	AllocationID string    `json:"allocation_id,omitempty"`// Target allocation identifier (if applicable)
	IPAddress    string    `json:"ip_address"`             // Remote client IP address of the caller
	Metadata     string    `json:"metadata"`               // Contextual metadata stored as JSON string
	CreatedAt    time.Time `json:"created_at"`
}
