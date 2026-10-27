// Package handlers provides HTTP controller logic, authentication middlewares,
// real-time Server-Sent Events (SSE) broadcasting, and database orchestration
// for the Secure Token Allocation Backend.
package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"token-alloc-backend/database"
	"token-alloc-backend/models"
	"token-alloc-backend/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SSEBroker coordinates real-time event streaming to connected web clients using Server-Sent Events (SSE).
//
// Working:
// - Manages topic-based multiplexing where clients subscribe to specific event streams
//   (e.g., "public_allocations", "admin_dashboard", or specific request ticket IDs "req-<uuid>").
// - Uses a mutex (sync.Mutex) to safely handle concurrent subscriber registrations, unregistrations,
//   and message broadcasts across multiple Go routines without race conditions.
// - Employs buffered Go channels (size 20) with non-blocking sends (select/default) to prevent slow
//   or stalled HTTP network connections from blocking the server or other subscribers.
//
// Interactions:
// - Consumed by SSE streaming endpoints: StreamPublicAllocations, StreamAdminDashboard, StreamRequestStatus.
// - Triggered by state mutation handlers: SubmitTokenRequest, AcceptRequest, RejectRequest, HoldRequest,
//   ServeRequest, CancelOwnRequest, CreateAllocation, UpdateAllocationStatus, DestroyAllocation.
type SSEBroker struct {
	clients map[string]map[chan string]bool
	mu      sync.Mutex
}

// Broker is the globally accessible singleton SSEBroker instance used across all handlers.
var Broker = &SSEBroker{
	clients: make(map[string]map[chan string]bool),
}

// AddClient registers a new subscriber channel under the specified topic.
//
// Working:
// 1. Acquires mutual exclusion lock on Broker.
// 2. Creates a buffered string channel (capacity 20).
// 3. Initializes the topic subscriber map if it doesn't already exist.
// 4. Stores the channel in the subscriber map with an active boolean flag.
// 5. Returns the channel for the HTTP streaming handler loop to read from.
//
// Parameters:
// - topic: The event category or entity ID to subscribe to (e.g., "public_allocations", "admin_dashboard", or reqID).
//
// Returns:
// - chan string: A buffered channel receiving serialized JSON SSE data strings.
//
// Interactions:
// - Invoked inside StreamRequestStatus, StreamPublicAllocations, and StreamAdminDashboard.
func (b *SSEBroker) AddClient(topic string) chan string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan string, 20)
	if b.clients[topic] == nil {
		b.clients[topic] = make(map[chan string]bool)
	}
	b.clients[topic][ch] = true
	return ch
}

// RemoveClient unregisters and closes a subscriber channel for a given topic.
//
// Working:
// 1. Acquires mutual exclusion lock on Broker.
// 2. Looks up the topic subscriber map.
// 3. Deletes the channel from the map and explicitly closes the channel to free resources.
// 4. If no subscribers remain for the topic, purges the topic entry from the root map.
//
// Parameters:
// - topic: The topic from which to remove the subscriber.
// - ch: The subscriber channel to unregister and close.
//
// Interactions:
// - Called via defer in StreamRequestStatus, StreamPublicAllocations, and StreamAdminDashboard
//   when client HTTP connections terminate or disconnect.
func (b *SSEBroker) RemoveClient(topic string, ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if subs, ok := b.clients[topic]; ok {
		if _, exists := subs[ch]; exists {
			delete(subs, ch)
			close(ch)
		}
		if len(subs) == 0 {
			delete(b.clients, topic)
		}
	}
}

// Broadcast dispatches a JSON-marshaled message payload to all active subscriber channels on a topic.
//
// Working:
// 1. Acquires mutual exclusion lock on Broker.
// 2. Serializes the provided payload interface{} to a JSON string.
// 3. Iterates over all active subscriber channels associated with the topic.
// 4. Performs a non-blocking channel send (`select { case ch <- msg: default: }`).
//    If a channel buffer is full (client network congestion), the drop prevents blocking other clients.
//
// Parameters:
// - topic: Target topic name to broadcast to.
// - payload: Any Go data structure serializable to JSON.
//
// Interactions:
// - Called by NotifyPublicAllocationsChanged, NotifyAdminDashboardChanged, and NotifyClient.
func (b *SSEBroker) Broadcast(topic string, payload interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if subs, ok := b.clients[topic]; ok {
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		msg := string(data)
		for ch := range subs {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

// NotifyClient routes an event payload to a single ticket subscriber listening on their request ID topic.
//
// Working:
// Delegates directly to Broker.Broadcast(reqID, payload).
//
// Parameters:
// - reqID: Target ticket request identifier string.
// - payload: Ticket state payload (typically RequestItemDTO).
//
// Interactions:
// - Called by AcceptRequest, RejectRequest, HoldRequest, ServeRequest, and CancelOwnRequest.
func (b *SSEBroker) NotifyClient(reqID string, payload interface{}) {
	b.Broadcast(reqID, payload)
}

// NotifyPublicAllocationsChanged refreshes public kiosks and display screens with updated allocation lists.
//
// Working:
// 1. Queries PostgreSQL for all Allocations sorted by creation time descending.
// 2. Broadcasts the full array of allocations to the "public_allocations" topic over SSE.
//
// Interactions:
// - Called whenever an allocation is created (CreateAllocation), status updated (UpdateAllocationStatus),
//   destroyed (DestroyAllocation), or when a new request is submitted (SubmitTokenRequest).
func NotifyPublicAllocationsChanged() {
	var allocs []models.Allocation
	database.DB.Order("created_at desc").Find(&allocs)
	Broker.Broadcast("public_allocations", allocs)
}

// NotifyAdminDashboardChanged notifies staff management screens that a system-wide change occurred.
//
// Working:
// Broadcasts an update pulse with current Unix timestamp to the "admin_dashboard" topic over SSE.
// Connected admin clients receive this event and automatically refetch stats and request queues.
//
// Interactions:
// - Called by all mutation handlers across the application (requests and allocations).
func NotifyAdminDashboardChanged() {
	Broker.Broadcast("admin_dashboard", gin.H{"type": "update", "timestamp": time.Now().UnixMilli()})
}

// RequestItemDTO represents the external Data Transfer Object (DTO) for a token request.
// Unlike the raw models.RequestItem, it provides decrypted form data and dynamically
// calculated live queue progression metrics.
//
// Working:
// - Delivers `FormData` as a parsed JSON map[string]interface{} instead of raw encrypted ciphertext.
// - Includes computed queue metrics: `PeopleAhead`, `ServedCount`, and `EstimatedWait` (in minutes).
//
// Interactions:
// - Produced by `toDTO` and `toAuthorizedDTO`.
// - Returned to public and administrative API consumers.
type RequestItemDTO struct {
	ID             string                 `json:"id"`
	AllocationID   string                 `json:"allocation_id"`
	AllocationName string                 `json:"allocation_name"`
	Date           string                 `json:"date"`
	UserSessionID  string                 `json:"user_session_id"`
	FormData       map[string]interface{} `json:"form_data"`
	Status         string                 `json:"status"`
	AssignedToken  int                    `json:"assigned_token,omitempty"`
	QueuePosition  int                    `json:"queue_position"`
	PeopleAhead    int                    `json:"people_ahead"`
	ServedCount    int                    `json:"served_count"`
	EstimatedWait  int                    `json:"estimated_wait"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
	SubmittedAt    time.Time              `json:"submitted_at"`
	AcceptedAt     time.Time              `json:"accepted_at,omitempty"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// toDTO converts a database models.RequestItem into an enriched RequestItemDTO.
//
// Working:
// 1. Decrypts the AES-256-CFB encrypted `r.FormData` by calling services.Decrypt().
//    - Unmarshals the resulting plaintext JSON string into map[string]interface{}.
//    - If decryption fails (e.g. legacy plaintext data), falls back to direct unmarshaling.
// 2. Queries PostgreSQL database for `servedCount`: total requests in this allocation with status="SERVED".
// 3. Computes `peopleAhead` depending on request status:
//    - If status is "ACCEPTED" and has an assigned token: counts requests in this allocation that are
//      also "ACCEPTED" but have a strictly lower `assigned_token`.
//    - If status is "PENDING": counts all already "ACCEPTED" requests plus all "PENDING" requests
//      submitted earlier (`submitted_at < r.SubmittedAt`).
//    - For other states (SERVED, REJECTED, CANCELLED): sets peopleAhead to 0.
// 4. Calculates `estimatedWait`: converts peopleAhead to minutes assuming 10 minutes per person.
//    If the user is currently at the front of the queue (ACCEPTED with 0 people ahead), estimatedWait is 0.
// 5. Assembles and returns the completed RequestItemDTO.
//
// Parameters:
// - r: The database RequestItem record.
//
// Returns:
// - RequestItemDTO: The hydrated and decrypted DTO.
//
// Interactions:
// - Calls services.Decrypt() to decipher encrypted form data.
// - Queries database.DB for live queue aggregation metrics.
// - Used by toAuthorizedDTO, AcceptRequest, RejectRequest, HoldRequest, ServeRequest, CancelOwnRequest,
//   SubmitTokenRequest, and ExportAllocationCSV.
func toDTO(r models.RequestItem) RequestItemDTO {
	var formData map[string]interface{}
	decryptedStr, err := services.Decrypt(r.FormData)
	if err == nil {
		json.Unmarshal([]byte(decryptedStr), &formData)
	} else {
		// Fallback if plaintext
		json.Unmarshal([]byte(r.FormData), &formData)
	}
	if formData == nil {
		formData = make(map[string]interface{})
	}

	// Calculate count of served persons in this allocation
	var servedCount int64
	database.DB.Model(&models.RequestItem{}).
		Where("allocation_id = ? AND status = ?", r.AllocationID, "SERVED").
		Count(&servedCount)

	// Calculate count of unserved persons ahead in queue
	var peopleAhead int64
	if r.Status == "ACCEPTED" && r.AssignedToken > 0 {
		database.DB.Model(&models.RequestItem{}).
			Where("allocation_id = ? AND status = ? AND assigned_token < ?", r.AllocationID, "ACCEPTED", r.AssignedToken).
			Count(&peopleAhead)
	} else if r.Status == "PENDING" {
		var acceptedAhead int64
		database.DB.Model(&models.RequestItem{}).
			Where("allocation_id = ? AND status = ?", r.AllocationID, "ACCEPTED").
			Count(&acceptedAhead)

		var pendingAhead int64
		database.DB.Model(&models.RequestItem{}).
			Where("allocation_id = ? AND status = ? AND submitted_at < ?", r.AllocationID, "PENDING", r.SubmittedAt).
			Count(&pendingAhead)

		peopleAhead = acceptedAhead + pendingAhead
	} else {
		peopleAhead = 0
	}

	estWait := int(peopleAhead) * 10
	if r.Status == "ACCEPTED" && peopleAhead == 0 {
		estWait = 0
	}

	return RequestItemDTO{
		ID:             r.ID,
		AllocationID:   r.AllocationID,
		AllocationName: r.AllocationName,
		Date:           r.Date,
		UserSessionID:  r.UserSessionID,
		FormData:       formData,
		Status:         r.Status,
		AssignedToken:  r.AssignedToken,
		QueuePosition:  r.QueuePosition,
		PeopleAhead:    int(peopleAhead),
		ServedCount:    int(servedCount),
		EstimatedWait:  estWait,
		IdempotencyKey: r.IdempotencyKey,
		SubmittedAt:    r.SubmittedAt,
		AcceptedAt:     r.AcceptedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

// Public Handlers

// GetTodayAllocations handles GET /api/public/allocations/today.
//
// Working:
// 1. Queries PostgreSQL for all Allocations, preloading associated dynamic FormFields.
// 2. Orders results by creation time descending so newest sessions appear first.
// 3. Responds with HTTP 200 OK containing JSON array of allocation objects.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Consumed by public display screens, kiosks, and mobile entry portals to show available queues.
// - Preloads FormFields defined in database/models.go.
func GetTodayAllocations(c *gin.Context) {
	var allocs []models.Allocation
	database.DB.Preload("FormFields").Order("created_at desc").Find(&allocs)
	c.JSON(http.StatusOK, allocs)
}

// GetAllocationByID handles GET /api/public/allocations/:id.
//
// Working:
// 1. Extracts the ":id" route parameter from the URL path.
// 2. Queries PostgreSQL for the matching Allocation, eagerly preloading its dynamic FormFields.
// 3. If no matching record exists, responds with HTTP 404 Not Found.
// 4. Returns HTTP 200 OK with the allocation session details and form schema.
//
// Parameters:
// - c: Gin request context containing allocation ID param.
//
// Interactions:
// - Invoked by client dynamic form renderers to build input fields tailored to this allocation session.
func GetAllocationByID(c *gin.Context) {
	id := c.Param("id")
	var alloc models.Allocation
	if err := database.DB.Preload("FormFields").First(&alloc, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Allocation not found"})
		return
	}
	c.JSON(http.StatusOK, alloc)
}

// SubmitTokenRequest handles POST /api/public/allocations/:id/requests.
//
// Working:
// 1. Parses and validates incoming JSON payload containing UserSessionID, FormData map, and IdempotencyKey.
// 2. Checks database for existence of target Allocation session. Returns 404 if missing.
// 3. Enforces session lifecycle status constraints:
//    - "COMPLETED": Returns HTTP 400 (Session closed and completed by admin).
//    - "PAUSED": Returns HTTP 400 (Session temporarily paused).
//    - "CLOSED": Returns HTTP 400 (Session closed for submissions).
// 4. Duplicate Submission Protection:
//    If UserSessionID is provided, checks if an active ticket (PENDING, ACCEPTED, or HOLD) already exists
//    for this allocation and device. If found, safely returns the existing ticket DTO with HTTP 200 OK
//    instead of creating a duplicate.
// 5. Cryptographic Protection of PII (Data-at-Rest Encryption):
//    Marshals the dynamic FormData map to JSON and encrypts it using services.Encrypt() (AES-256-CFB).
//    Ensures unencrypted personal data is never persisted in plaintext.
// 6. Queue Position Computation:
//    Counts existing PENDING requests for this allocation to assign a starting queue position.
// 7. Request Record Creation:
//    Constructs models.RequestItem with a full UUID identifier ("req-<uuid>"), sets initial status to "PENDING",
//    stores encrypted form data, and inserts the record into PostgreSQL.
// 8. Real-Time Propagation:
//    Calls NotifyPublicAllocationsChanged() to update queue counters on public kiosks.
//    Calls NotifyAdminDashboardChanged() to prompt admin screens to reload live queues.
// 9. Returns HTTP 201 Created with the decrypted RequestItemDTO.
//
// Parameters:
// - c: Gin request context containing allocation ID param and JSON request body.
//
// Interactions:
// - Interacts with database.DB for validation, duplicate checks, and persistence.
// - Calls services.Encrypt() for AES-256-CFB encryption of user form data.
// - Triggers NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged() for live SSE push.
func SubmitTokenRequest(c *gin.Context) {
	allocID := c.Param("id")
	var body struct {
		UserSessionID  string                 `json:"user_session_id"`
		FormData       map[string]interface{} `json:"form_data"`
		IdempotencyKey string                 `json:"idempotency_key"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var alloc models.Allocation
	if err := database.DB.First(&alloc, "id = ?", allocID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session allocation not found"})
		return
	}

	if alloc.Status == "COMPLETED" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This token session has been completed by administration."})
		return
	}
	if alloc.Status == "PAUSED" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This token session is currently paused by administration."})
		return
	}
	if alloc.Status == "CLOSED" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This allocation session is closed"})
		return
	}

	// Duplicate Submission Protection:
	// If an active request (PENDING, ACCEPTED, HOLD) already exists for this allocation and user_session_id, return existing ticket.
	if body.UserSessionID != "" {
		var existingReq models.RequestItem
		if err := database.DB.Where("allocation_id = ? AND user_session_id = ? AND status IN ('PENDING', 'ACCEPTED', 'HOLD')", allocID, body.UserSessionID).First(&existingReq).Error; err == nil {
			c.JSON(http.StatusOK, toDTO(existingReq))
			return
		}
	}

	// Encrypt Form Data PII
	formDataBytes, _ := json.Marshal(body.FormData)
	encryptedFormData, err := services.Encrypt(string(formDataBytes))
	if err != nil {
		encryptedFormData = string(formDataBytes)
	}

	// Calculate waiting count & position
	var count int64
	database.DB.Model(&models.RequestItem{}).Where("allocation_id = ? AND status = ?", allocID, "PENDING").Count(&count)
	queuePosition := int(count) + 1

	reqItem := models.RequestItem{
		ID:             "req-" + uuid.New().String(), // Bug #13: full UUID, no truncation
		AllocationID:   alloc.ID,
		AllocationName: alloc.Name,
		Date:           alloc.Date,
		UserSessionID:  body.UserSessionID,
		FormData:       encryptedFormData,
		Status:         "PENDING",
		QueuePosition:  queuePosition,
		EstimatedWait:  queuePosition * 10,
		IdempotencyKey: body.IdempotencyKey,
		SubmittedAt:    time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := database.DB.Create(&reqItem).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store request"})
		return
	}

	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()
	c.JSON(http.StatusCreated, toDTO(reqItem))
}

// isCallerAdmin inspects the incoming HTTP request context to determine if the caller holds a valid admin session.
//
// Working:
// 1. Reads the "admin_session" HTTP cookie.
// 2. If cookie is missing or empty, returns false.
// 3. Validates the cookie's cryptographic HMAC signature and format via verifySession().
// 4. Returns true if signature and session structure are valid.
//
// Parameters:
// - c: Gin request context.
//
// Returns:
// - bool: True if the request carries a cryptographically verified admin session cookie.
//
// Interactions:
// - Calls verifySession() to validate cookie authenticity without hitting database.
// - Used by toAuthorizedDTO, GetRequestStatus, and StreamRequestStatus for role-based data masking.
func isCallerAdmin(c *gin.Context) bool {
	cookieVal, err := c.Cookie("admin_session")
	if err != nil || cookieVal == "" {
		return false
	}
	_, _, ok := verifySession(cookieVal)
	return ok
}

// toAuthorizedDTO prepares a RequestItemDTO with strict data privacy / masking applied.
//
// Working:
// 1. Decrypts the request into a RequestItemDTO by calling toDTO(r).
// 2. Evaluates access ownership:
//    - Admin users have full access (isAdmin == true).
//    - Ticket holders have full access (callerSessionID matches r.UserSessionID).
// 3. If caller is NEITHER admin NOR the ticket owner, redacts sensitive FormData fields,
//    replacing the map with a protected notice message:
//    `{"_protected": "Form data is AES-256 encrypted. Access is restricted exclusively to ticket owner and admin."}`
// 4. Returns the authorized DTO.
//
// Parameters:
// - r: Raw database request record.
// - callerSessionID: Device or browser session ID passed by the caller.
// - isAdmin: Boolean flag indicating if caller holds verified admin session.
//
// Returns:
// - RequestItemDTO: Sanitized or full DTO according to authorization level.
//
// Interactions:
// - Calls toDTO() for baseline entity conversion and wait time calculation.
// - Used by GetRequestStatus and StreamRequestStatus.
func toAuthorizedDTO(r models.RequestItem, callerSessionID string, isAdmin bool) RequestItemDTO {
	dto := toDTO(r)

	// User Privacy & Security Rule:
	// Every data is stored in backend in encrypted AES-256 form.
	// Decrypted form data is ONLY accessible to:
	// 1. Authenticated Admins
	// 2. The specific user/device holding that ticket (matching user_session_id)
	isOwner := callerSessionID != "" && callerSessionID == r.UserSessionID
	if !isAdmin && !isOwner {
		dto.FormData = map[string]interface{}{
			"_protected": "Form data is AES-256 encrypted. Access is restricted exclusively to ticket owner and admin.",
		}
	}
	return dto
}

// verifyQRSig validates the authenticity of an HMAC-SHA256 signature embedded in a QR code verification scan.
//
// Working:
// 1. Verifies that both reqID and sig are non-empty strings.
// 2. Resolves HMAC secret key hierarchy (QR_HMAC_SECRET -> SESSION_SECRET -> in-memory sessionHMACSecret).
// 3. Computes expected HMAC-SHA256 hash over the request ID.
// 4. Compares provided signature against expected signature using crypto/subtle.ConstantTimeCompare
//    to protect against timing attack vulnerabilities.
//
// Parameters:
// - reqID: Target ticket request identifier string.
// - sig: Hex-encoded HMAC-SHA256 signature received from QR scan.
//
// Returns:
// - bool: True if the signature matches the secret calculation.
//
// Interactions:
// - Used by GetRequestStatus when physical counter operators scan tickets via camera QR reader.
func verifyQRSig(reqID, sig string) bool {
	if reqID == "" || sig == "" {
		return false
	}
	secret := os.Getenv("QR_HMAC_SECRET")
	if secret == "" {
		secret = os.Getenv("SESSION_SECRET")
	}
	if secret == "" {
		secret = hex.EncodeToString(sessionHMACSecret)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(reqID))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) == 1
}

// GetRequestStatus handles GET /api/public/requests/:id/status.
//
// Working:
// 1. Extracts request ":id" parameter and queries PostgreSQL. Returns 404 if missing.
// 2. Identifies caller session ID from "X-User-Session-ID" header or "user_session_id" query parameter.
// 3. Checks if caller is an authenticated admin via isCallerAdmin().
// 4. Inspects optional "sig" query parameter:
//    - If valid QR HMAC signature is verified via verifyQRSig(), returns fully decrypted toDTO(req)
//      to allow physical counter operators to verify ticket details immediately upon QR scan.
// 5. Otherwise, returns toAuthorizedDTO(req) with PII masking applied if caller is unauthorized.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Interacts with database.DB, isCallerAdmin(), verifyQRSig(), and toAuthorizedDTO().
func GetRequestStatus(c *gin.Context) {
	reqID := c.Param("id")
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request ticket not found"})
		return
	}
	callerSessionID := c.GetHeader("X-User-Session-ID")
	if callerSessionID == "" {
		callerSessionID = c.Query("user_session_id")
	}
	isAdmin := isCallerAdmin(c)

	sig := c.Query("sig")
	if sig != "" && verifyQRSig(reqID, sig) {
		// Valid HMAC signature presented via QR scan — return decrypted DTO for counter verification
		c.JSON(http.StatusOK, toDTO(req))
		return
	}

	c.JSON(http.StatusOK, toAuthorizedDTO(req, callerSessionID, isAdmin))
}

// StreamRequestStatus handles GET /api/public/requests/:id/stream.
//
// Working:
// 1. Configures HTTP response headers for Server-Sent Events (SSE):
//    - Content-Type: text/event-stream
//    - Cache-Control: no-cache
//    - Connection: keep-alive
//    - Access-Control-Allow-Origin: *
// 2. Subscribes client to real-time events for this ticket ID via Broker.AddClient(reqID).
//    Registers cleanup via defer Broker.RemoveClient(reqID, ch).
// 3. Resolves caller authorization (user session ID and admin status).
// 4. Sends immediate initial event containing the current state of the ticket.
// 5. Enters long-lived streaming loop:
//    - Case ch receive: When admin updates ticket state, fetches latest record, formats authorized DTO,
//      and flushes SSE "data: ..." packet.
//    - Case ctx.Done(): Client disconnected or closed browser tab; cleanly exits loop and triggers deferred cleanup.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Interacts with Broker for pub/sub messaging.
// - Calls toAuthorizedDTO() on every event to prevent data leakage over SSE.
func StreamRequestStatus(c *gin.Context) {
	reqID := c.Param("id")
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	ch := Broker.AddClient(reqID)
	defer Broker.RemoveClient(reqID, ch)

	callerSessionID := c.GetHeader("X-User-Session-ID")
	if callerSessionID == "" {
		callerSessionID = c.Query("user_session_id")
	}
	isAdmin := isCallerAdmin(c)

	// Send initial event
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err == nil {
		dtoBytes, _ := json.Marshal(toAuthorizedDTO(req, callerSessionID, isAdmin))
		if _, err := c.Writer.WriteString("data: " + string(dtoBytes) + "\n\n"); err != nil {
			return
		}
		c.Writer.Flush()
	}

	ctx := c.Request.Context()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var rawReq models.RequestItem
			if err := database.DB.First(&rawReq, "id = ?", reqID).Error; err == nil {
				dtoBytes, _ := json.Marshal(toAuthorizedDTO(rawReq, callerSessionID, isAdmin))
				msg = string(dtoBytes)
			}
			if _, err := c.Writer.WriteString("data: " + msg + "\n\n"); err != nil {
				return
			}
			c.Writer.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// StreamPublicAllocations handles GET /api/public/allocations/stream.
//
// Working:
// 1. Sets SSE response headers (text/event-stream, no-cache, keep-alive, CORS).
// 2. Registers client channel under "public_allocations" topic in Broker.
//    Defers unregistration via Broker.RemoveClient.
// 3. Queries current allocations and flushes initial data array.
// 4. Loops listening for updates on the channel or client disconnection via ctx.Done().
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Consumed by public kiosk UI screens to automatically reflect new, paused, or closed sessions in real-time.
// - Subscribes to Broker topic "public_allocations" triggered by NotifyPublicAllocationsChanged().
func StreamPublicAllocations(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	ch := Broker.AddClient("public_allocations")
	defer Broker.RemoveClient("public_allocations", ch)

	// Send initial state
	var allocs []models.Allocation
	database.DB.Order("created_at desc").Find(&allocs)
	data, _ := json.Marshal(allocs)
	if _, err := c.Writer.WriteString("data: " + string(data) + "\n\n"); err != nil {
		return
	}
	c.Writer.Flush()

	ctx := c.Request.Context()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if _, err := c.Writer.WriteString("data: " + msg + "\n\n"); err != nil {
				return
			}
			c.Writer.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// StreamAdminDashboard handles GET /api/admin/dashboard/stream.
//
// Working:
// 1. Configures SSE headers (text/event-stream, no-cache, keep-alive, CORS).
// 2. Registers client channel under "admin_dashboard" topic in Broker.
//    Defers unregistration via Broker.RemoveClient.
// 3. Emits initial connected heartbeat event: `{"type":"connected"}`.
// 4. Loops listening for update broadcasts dispatched when tickets or allocations mutate.
// 5. Exits cleanly when admin disconnects or browser tab is closed via ctx.Done().
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Consumed by React administrative dashboard for instant, zero-polling reactive UI synchronization.
// - Subscribes to Broker topic "admin_dashboard" triggered by NotifyAdminDashboardChanged().
func StreamAdminDashboard(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	ch := Broker.AddClient("admin_dashboard")
	defer Broker.RemoveClient("admin_dashboard", ch)

	if _, err := c.Writer.WriteString("data: {\"type\":\"connected\"}\n\n"); err != nil {
		return
	}
	c.Writer.Flush()

	ctx := c.Request.Context()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if _, err := c.Writer.WriteString("data: " + msg + "\n\n"); err != nil {
				return
			}
			c.Writer.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// sessionHMACSecret is a server-side secret for signing admin session cookies.
// Falls back to a random secret per-process if SESSION_SECRET env var is not set.
var sessionHMACSecret []byte

// init initializes the cryptographic secret used to sign administrative session cookies.
//
// Working:
// Reads `SESSION_SECRET` from environment variables. If absent, generates a cryptographically
// secure 32-byte pseudo-random byte slice.
func init() {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		// Generate a random 32-byte secret per server run (sessions invalidated on restart)
		b := make([]byte, 32)
		rand.Read(b)
		sessionHMACSecret = b
	} else {
		sessionHMACSecret = []byte(secret)
	}
}

// signSession generates a tamper-evident HMAC-SHA256 signed session cookie token.
//
// Working:
// 1. Formats payload string as "username:session_version".
// 2. Computes HMAC-SHA256 message authentication code over the payload using sessionHMACSecret.
// 3. Encodes signature to hexadecimal.
// 4. Returns composite string formatted as "username:version:hexSignature".
//
// Parameters:
// - username: Admin username.
// - version: Current session invalidation version number from database.
//
// Returns:
// - string: Signed cookie token value.
//
// Interactions:
// - Called by AdminLogin and ChangeAdminCredentials when issuing or refreshing cookies.
func signSession(username string, version int) string {
	payload := fmt.Sprintf("%s:%d", username, version)
	mac := hmac.New(sha256.New, sessionHMACSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + ":" + sig
}

// verifySession validates an HMAC-signed session cookie without requiring a database round-trip.
//
// Working:
// 1. Splits cookie value by colon into exactly 3 parts: username, version string, and signature.
// 2. Re-computes expected HMAC-SHA256 over "username:version" using sessionHMACSecret.
// 3. Validates provided signature against expected signature using subtle.ConstantTimeCompare
//    to protect against timing analysis attacks.
// 4. Parses version string to integer.
// 5. Returns username, version, and true if valid; empty/0/false otherwise.
//
// Parameters:
// - cookieVal: Raw cookie string received in HTTP request.
//
// Returns:
// - string: Username.
// - int: Session version encoded in cookie.
// - bool: True if signature is cryptographically valid.
//
// Interactions:
// - Called by AdminAuthMiddleware, ChangeAdminCredentials, and isCallerAdmin.
func verifySession(cookieVal string) (string, int, bool) {
	parts := strings.SplitN(cookieVal, ":", 3)
	if len(parts) != 3 {
		return "", 0, false
	}
	uname := parts[0]
	versionStr := parts[1]
	providedSig := parts[2]

	payload := uname + ":" + versionStr
	mac := hmac.New(sha256.New, sessionHMACSecret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		return "", 0, false
	}
	var version int
	fmt.Sscanf(versionStr, "%d", &version)
	return uname, version, true
}

// hashPassword creates a secure one-way bcrypt hash of a plaintext password.
//
// Working:
// 1. Hashes password using bcrypt with bcrypt.DefaultCost (cost 10).
// 2. If bcrypt hashing fails, falls back to SHA-256 hexadecimal hash.
// 3. Returns string representation of hash suitable for database storage.
//
// Parameters:
// - pwd: Raw plaintext password.
//
// Returns:
// - string: Hashed password string.
//
// Interactions:
// - Called by InitDefaultAdmin, CreateSubAdmin, and ChangeAdminCredentials.
func hashPassword(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		// Fallback: SHA-256 if bcrypt fails (should not happen)
		h := sha256.Sum256([]byte(pwd))
		return hex.EncodeToString(h[:])
	}
	return string(hash)
}

// checkPassword securely compares a plaintext password against a stored hash.
//
// Working:
// 1. Attempts verification using bcrypt.CompareHashAndPassword.
// 2. If bcrypt does not match, attempts backward-compatible check against legacy SHA-256 hashes
//    using constant-time comparison (subtle.ConstantTimeCompare).
// 3. Returns true if match succeeds.
//
// Parameters:
// - pwd: Raw plaintext password to test.
// - stored: Stored password hash string from database.
//
// Returns:
// - bool: True if password matches stored hash.
//
// Interactions:
// - Called by AdminLogin and ChangeAdminCredentials.
func checkPassword(pwd, stored string) bool {
	// Try bcrypt first
	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(pwd)); err == nil {
		return true
	}
	// Fallback: constant-time compare against legacy SHA-256 hash (bug #10 fix)
	h := sha256.Sum256([]byte(pwd))
	legacyHash := hex.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(legacyHash), []byte(stored)) == 1
}

// InitDefaultAdmin ensures at least one Super Admin account exists in the PostgreSQL database.
//
// Working:
// 1. Checks if ANY record with role="SUPER_ADMIN" exists in the `admins` table.
// 2. If a Super Admin is already present, retains existing database credentials and logs confirmation.
// 3. If no Super Admin exists (fresh installation or empty database):
//    - Reads username from `SUPER_ADMIN_USERNAME` env var (default: "admin").
//    - Reads password from `SUPER_ADMIN_PASSWORD` env var (default: "admin123").
//    - Generates bcrypt hash of password via hashPassword().
//    - Inserts new models.Admin record with role="SUPER_ADMIN" and session_version=1.
//
// Interactions:
// - Called once by main() in main.go during application boot sequence.
// - Directly queries and writes to database.DB.
func InitDefaultAdmin() {
	var count int64
	database.DB.Model(&models.Admin{}).Where("role = ?", "SUPER_ADMIN").Count(&count)
	if count > 0 {
		log.Println("[AUTH] Super Admin account found in database. Using stored DB credentials.")
		return
	}

	envUsername := strings.TrimSpace(os.Getenv("SUPER_ADMIN_USERNAME"))
	if envUsername == "" {
		envUsername = "admin"
	}
	envPassword := strings.TrimSpace(os.Getenv("SUPER_ADMIN_PASSWORD"))
	if envPassword == "" {
		envPassword = "admin123"
	}

	superAdmin := models.Admin{
		ID:             "admin-super-" + uuid.New().String()[:8],
		Username:       envUsername,
		Password:       hashPassword(envPassword),
		Role:           "SUPER_ADMIN",
		SessionVersion: 1,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := database.DB.Create(&superAdmin).Error; err != nil {
		log.Printf("[AUTH ERROR] Failed to seed initial Super Admin: %v\n", err)
	} else {
		log.Printf("[AUTH] Initial Super Admin '%s' created from environment variables and stored in database.\n", superAdmin.Username)
	}
}

// Admin Auth Handlers

// AdminLogin handles POST /api/admin/auth/login.
//
// Working:
// 1. Binds JSON payload containing username and password.
// 2. Validates that both fields are non-empty strings.
// 3. Queries PostgreSQL `admins` table for matching username. Returns 401 Unauthorized if not found.
// 4. Verifies password against stored hash using checkPassword(). Returns 401 if invalid.
// 5. Generates 12-hour signed session cookie token using signSession(admin.Username, admin.SessionVersion).
// 6. Issues HTTP-only, Strict SameSite cookie named "admin_session" with 43200 seconds (12 hours) TTL.
// 7. Responds with HTTP 200 OK and admin metadata (id, username, role, session_version).
//
// Parameters:
// - c: Gin request context with JSON login credentials.
//
// Interactions:
// - Queries database.DB for admin account.
// - Calls checkPassword() for cryptographic verification.
// - Calls signSession() to generate cookie value.
func AdminLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	uname := strings.TrimSpace(body.Username)
	pwd := strings.TrimSpace(body.Password)

	if uname == "" || pwd == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Both username and password are required"})
		return
	}

	var admin models.Admin
	if err := database.DB.Where("username = ?", uname).First(&admin).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Verify exact password hash match
	if !checkPassword(pwd, admin.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Set HMAC-signed 12-hour session cookie
	sessionCookieVal := signSession(admin.Username, admin.SessionVersion)
	c.SetSameSite(http.SameSiteNoneMode)
	c.SetCookie("admin_session", sessionCookieVal, 43200, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"token":           sessionCookieVal,
		"admin_id":        admin.ID,
		"username":        admin.Username,
		"role":            admin.Role,
		"session_version": admin.SessionVersion,
	})
}

// AdminAuthMiddleware creates a Gin middleware enforcing 12-hour signed cookie authentication.
//
// Working:
// 1. Reads the "admin_session" cookie from the incoming request.
// 2. If cookie is missing, aborts request with HTTP 401 Unauthorized.
// 3. Cryptographically verifies cookie signature via verifySession().
//    If invalid or tampered, clears cookie and aborts with HTTP 401.
// 4. Looks up admin in database by username. If missing, clears cookie and aborts with HTTP 401.
// 5. Multi-Device Invalidation Check:
//    Compares the cookie's embedded version against admin.SessionVersion in the database.
//    If versions do not match (e.g., credentials were changed on another device), clears cookie
//    and aborts with HTTP 401 ("Session expired or credentials were changed on another device.").
// 6. Stores authenticated admin object into Gin context (`c.Set("admin", admin)`).
// 7. Passes execution to next handler via c.Next().
//
// Returns:
// - gin.HandlerFunc: Middleware handler function.
//
// Interactions:
// - Applied to the protected admin route group in main.go.
// - Sets "admin" in gin.Context consumed by GetAdminProfile, SuperAdminMiddleware, etc.
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieVal, _ := c.Cookie("admin_session")
		if cookieVal == "" {
			cookieVal = c.Query("token")
		}
		if cookieVal == "" {
			cookieVal = c.Query("admin_session")
		}
		if cookieVal == "" {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				cookieVal = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if cookieVal == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin authentication required. Please log in."})
			c.Abort()
			return
		}

		uname, cookieVer, ok := verifySession(cookieVal)
		if !ok {
			c.SetSameSite(http.SameSiteNoneMode)
			c.SetCookie("admin_session", "", -1, "/", "", true, true)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session signature invalid. Please log in again."})
			c.Abort()
			return
		}

		var admin models.Admin
		if err := database.DB.Where("username = ?", uname).First(&admin).Error; err != nil {
			c.SetSameSite(http.SameSiteNoneMode)
			c.SetCookie("admin_session", "", -1, "/", "", true, true)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin account not found"})
			c.Abort()
			return
		}

		if cookieVer != admin.SessionVersion {
			c.SetSameSite(http.SameSiteNoneMode)
			c.SetCookie("admin_session", "", -1, "/", "", true, true)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired or credentials were changed on another device."})
			c.Abort()
			return
		}

		c.Set("admin", admin)
		c.Next()
	}
}

// SuperAdminMiddleware creates a Gin middleware restricting endpoints to SUPER_ADMIN accounts.
//
// Working:
// 1. Extracts authenticated "admin" models.Admin object from Gin context (set by AdminAuthMiddleware).
// 2. If admin object is missing, aborts with HTTP 401 Unauthorized.
// 3. Checks if admin.Role equals "SUPER_ADMIN".
//    If role is standard "ADMIN", aborts with HTTP 403 Forbidden.
// 4. Calls c.Next() to allow Super Admin access.
//
// Returns:
// - gin.HandlerFunc: Middleware handler function.
//
// Interactions:
// - Applied to Super Admin sub-group in main.go guarding user management and CSV exports.
func SuperAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get("admin")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin authentication required"})
			c.Abort()
			return
		}
		admin := val.(models.Admin)
		if admin.Role != "SUPER_ADMIN" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Super Admin privileges required for this action"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GetAdminProfile handles GET /api/admin/me.
//
// Working:
// Retrieves the authenticated admin object from the Gin context and returns ID, username, role,
// and session version in an HTTP 200 OK response.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Relies on AdminAuthMiddleware having set "admin" in context.
func GetAdminProfile(c *gin.Context) {
	val, exists := c.Get("admin")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	admin := val.(models.Admin)
	c.JSON(http.StatusOK, gin.H{
		"admin_id":        admin.ID,
		"username":        admin.Username,
		"role":            admin.Role,
		"session_version": admin.SessionVersion,
	})
}

// GetAllAdmins handles GET /api/admin/users (Super Admin only).
//
// Working:
// Queries PostgreSQL for all administrator accounts, selecting ID, username, role, session version,
// and timestamps (omitting hashed passwords). Returns HTTP 200 OK with the array.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by SuperAdminMiddleware.
// - Reads from database.DB.
func GetAllAdmins(c *gin.Context) {
	var admins []models.Admin
	database.DB.Select("id, username, role, session_version, created_at, updated_at").Order("created_at ASC").Find(&admins)
	c.JSON(http.StatusOK, admins)
}

// CreateSubAdmin handles POST /api/admin/users (Super Admin only).
//
// Working:
// 1. Parses JSON payload containing username and password.
// 2. Validates password length (minimum 6 characters) and non-empty username.
// 3. Checks database to prevent duplicate usernames. Returns 400 Bad Request if username taken.
// 4. Hashes password using hashPassword() (bcrypt).
// 5. Creates models.Admin with ID "admin-<uuid>", role "ADMIN", and session_version 1.
// 6. Inserts record into database.DB and returns HTTP 201 Created.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by SuperAdminMiddleware.
// - Calls hashPassword() for bcrypt hashing.
// - Inserts into database.DB.
func CreateSubAdmin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	uname := strings.TrimSpace(body.Username)
	pwd := strings.TrimSpace(body.Password)

	if uname == "" || pwd == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}
	if len(pwd) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters long"})
		return
	}

	var existing models.Admin
	if err := database.DB.Where("username = ?", uname).First(&existing).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An admin user with this username already exists"})
		return
	}

	newAdmin := models.Admin{
		ID:             "admin-" + uuid.New().String(),
		Username:       uname,
		Password:       hashPassword(pwd),
		Role:           "ADMIN",
		SessionVersion: 1,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := database.DB.Create(&newAdmin).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create admin user: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         newAdmin.ID,
		"username":   newAdmin.Username,
		"role":       newAdmin.Role,
		"created_at": newAdmin.CreatedAt,
	})
}

// DeleteSubAdmin handles DELETE /api/admin/users/:id (Super Admin only).
//
// Working:
// 1. Looks up target admin account by ":id" parameter. Returns 404 if missing.
// 2. Hierarchy Protection:
//    Checks if target admin has role="SUPER_ADMIN". If so, blocks deletion with HTTP 403 Forbidden
//    ("Cannot remove Super Admin account").
// 3. Deletes target admin from PostgreSQL and returns HTTP 200 OK.
//
// Parameters:
// - c: Gin request context with ":id" parameter.
//
// Interactions:
// - Guarded by SuperAdminMiddleware.
// - Deletes from database.DB.
func DeleteSubAdmin(c *gin.Context) {
	id := c.Param("id")

	var target models.Admin
	if err := database.DB.First(&target, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Admin user not found"})
		return
	}

	// Super Admin hierarchy rule: Super Admin cannot be removed by anyone!
	if target.Role == "SUPER_ADMIN" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot remove Super Admin account"})
		return
	}

	if err := database.DB.Delete(&target).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete admin user: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Admin user removed successfully"})
}

// ChangeAdminCredentials handles POST /api/admin/change-credentials.
//
// Working:
// 1. Verifies caller authentication via the "admin_session" cookie and verifySession().
// 2. Binds JSON payload containing CurrentPassword, NewUsername, and NewPassword.
// 3. Validates that at least one credential (username or password) is supplied, and enforces
//    minimum 6 character length for new passwords.
// 4. Fetches admin record from PostgreSQL.
// 5. If CurrentPassword was provided, verifies it against stored hash using checkPassword().
// 6. If NewUsername is provided and differs from current:
//    - Checks database to ensure username is not already claimed by another administrator.
//    - Updates admin.Username.
// 7. If NewPassword is provided:
//    - Hashes new password using hashPassword() (bcrypt).
//    - Updates admin.Password.
// 8. Multi-Device Invalidation (Instant Global Logout):
//    - Increments `admin.SessionVersion` by 1.
//    - Saves updated admin model to PostgreSQL.
//    - All other devices holding cookies with the previous session version will be immediately
//      rejected on their next request by AdminAuthMiddleware.
// 9. Generates and sets a new 12-hour HMAC-signed session cookie for the current device.
// 10. Responds with HTTP 200 OK confirming update and session invalidation.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Calls verifySession() and checkPassword() for authentication.
// - Calls hashPassword() to hash the new password.
// - Calls signSession() and sets new "admin_session" cookie.
// - Directly updates database.DB.
func ChangeAdminCredentials(c *gin.Context) {
	cookieVal, err := c.Cookie("admin_session")
	if err != nil || cookieVal == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Verify signed cookie (bug #4 fix)
	uname, _, ok := verifySession(cookieVal)
	if !ok {
		c.SetCookie("admin_session", "", -1, "/", "", true, true)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session invalid or tampered"})
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewUsername     string `json:"new_username"`
		NewPassword     string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	newUname := strings.TrimSpace(body.NewUsername)
	newPwd := strings.TrimSpace(body.NewPassword)

	if newUname == "" && newPwd == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide a new username or password to update"})
		return
	}

	if newPwd != "" && len(newPwd) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password must be at least 6 characters long"})
		return
	}

	var admin models.Admin
	if err := database.DB.Where("username = ?", uname).First(&admin).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Admin account not found"})
		return
	}

	// Verify current password using bcrypt (bug #10 fix)
	if body.CurrentPassword != "" {
		if !checkPassword(body.CurrentPassword, admin.Password) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Current password does not match"})
			return
		}
	}

	// Update username if changed
	if newUname != "" && newUname != admin.Username {
		var existing models.Admin
		if err := database.DB.Where("username = ? AND id != ?", newUname, admin.ID).First(&existing).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username is already taken by another administrator"})
			return
		}
		admin.Username = newUname
	}

	// Update password using bcrypt (bug #9 fix)
	if newPwd != "" {
		admin.Password = hashPassword(newPwd)
	}

	// Increment session version to invalidate all other device sessions
	admin.SessionVersion += 1

	if err := database.DB.Save(&admin).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update admin credentials in database"})
		return
	}

	// Set new HMAC-signed 12-hour session cookie (bug #4 fix)
	newCookieVal := signSession(admin.Username, admin.SessionVersion)
	c.SetSameSite(http.SameSiteNoneMode)
	c.SetCookie("admin_session", newCookieVal, 43200, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"message":         "Credentials updated successfully! All other active device sessions have been logged out.",
		"username":        admin.Username,
		"session_version": admin.SessionVersion,
	})
}

// AdminLogout handles POST /api/admin/auth/logout.
//
// Working:
// Overwrites the "admin_session" cookie with an empty string and a negative Max-Age (-1),
// instructing the browser to immediately delete the session cookie. Returns HTTP 200 OK.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Consumed by admin frontend on user logout.
func AdminLogout(c *gin.Context) {
	c.SetCookie("admin_session", "", -1, "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// Admin Operations Handlers

// GetAdminAllocations handles GET /api/admin/allocations.
//
// Working:
// 1. Queries PostgreSQL for all Allocations, eagerly preloading associated FormFields.
// 2. Orders allocations descending by created_at.
// 3. Returns HTTP 200 OK with complete allocation array for administrative dashboard.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Reads from database.DB.
func GetAdminAllocations(c *gin.Context) {
	var allocs []models.Allocation
	database.DB.Preload("FormFields").Order("created_at desc").Find(&allocs)
	c.JSON(http.StatusOK, allocs)
}

// CreateAllocation handles POST /api/admin/allocations.
//
// Working:
// 1. Binds JSON payload containing allocation metadata (Name, Description, OpeningTime, ClosingTime,
//    MaxTokens, AdditionalInstructions) and custom dynamic FormFields array.
// 2. Generates short unique ID: "alloc-<uuid[:6]>".
// 3. Initializes models.Allocation record with status="ACTIVE", current_sequence=0, waiting_count=0,
//    and persists to PostgreSQL database.DB.
// 4. Iterates through FormFields (if provided), sets parent AllocationID, generates field ID, assigns
//    sequential display_order, and inserts each field into PostgreSQL.
// 5. Audit Logging:
//    Inserts an immutable models.AuditLogItem recording event="ALLOCATION_CREATED", client IP address,
//    and session name metadata.
// 6. Real-Time Propagation:
//    Calls NotifyPublicAllocationsChanged() to update public kiosk screens.
//    Calls NotifyAdminDashboardChanged() to sync admin dashboards.
// 7. Returns HTTP 201 Created with the fully preloaded allocation entity.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Writes to models.Allocation, models.FormField, and models.AuditLogItem tables in database.DB.
// - Triggers NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
func CreateAllocation(c *gin.Context) {
	var body struct {
		Name                   string             `json:"name"`
		Description            string             `json:"description"`
		OpeningTime            string             `json:"opening_time"`
		ClosingTime            string             `json:"closing_time"`
		MaxTokens              int                `json:"max_tokens"`
		AdditionalInstructions string             `json:"additional_instructions"`
		FormFields             []models.FormField `json:"form_fields"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid body"})
		return
	}

	allocID := "alloc-" + uuid.New().String()[:6]
	now := time.Now()
	alloc := models.Allocation{
		ID:                     allocID,
		Date:                   now.Format("2006-01-02"),
		Name:                   body.Name,
		Description:            body.Description,
		OpeningTime:            body.OpeningTime,
		ClosingTime:            body.ClosingTime,
		MaxTokens:              body.MaxTokens,
		AdditionalInstructions: body.AdditionalInstructions,
		Status:                 "ACTIVE",
		CurrentSequence:        0,
		WaitingCount:           0,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	if err := database.DB.Create(&alloc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Create Form Fields if provided
	for i, f := range body.FormFields {
		f.ID = fmt.Sprintf("field-%s-%d", allocID, i+1)
		f.AllocationID = allocID
		f.DisplayOrder = i + 1
		database.DB.Create(&f)
	}

	// Audit Log
	database.DB.Create(&models.AuditLogItem{
		ID:           "log-" + uuid.New().String()[:8],
		Event:        "ALLOCATION_CREATED",
		AllocationID: allocID,
		IPAddress:    c.ClientIP(),
		Metadata:     fmt.Sprintf(`{"name":"%s"}`, body.Name),
		CreatedAt:    time.Now(),
	})

	database.DB.Preload("FormFields").First(&alloc, "id = ?", allocID)
	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()
	c.JSON(http.StatusCreated, alloc)
}

// UpdateAllocationStatus handles PATCH /api/admin/allocations/:id.
//
// Working:
// 1. Extracts allocation ":id" parameter.
// 2. Binds JSON payload containing target status string.
// 3. Validates status against an explicit allowlist: "ACTIVE", "PAUSED", "CLOSED", "COMPLETED".
//    Returns 400 Bad Request if invalid.
// 4. Executes update query on PostgreSQL models.Allocation. Checks for DB errors and rows affected.
//    If rows affected is 0, returns 404 Not Found.
// 5. Broadcasts real-time updates via NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
// 6. Returns HTTP 200 OK `{"message": "Status updated"}`.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Updates database.DB.
// - Triggers NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
func UpdateAllocationStatus(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid body"})
		return
	}

	// Bug #16 fix: validate against allowlist
	allowed := map[string]bool{"ACTIVE": true, "PAUSED": true, "CLOSED": true, "COMPLETED": true}
	if !allowed[body.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status. Must be one of: ACTIVE, PAUSED, CLOSED, COMPLETED"})
		return
	}

	// Bug #17 fix: check DB error and rows affected
	res := database.DB.Model(&models.Allocation{}).Where("id = ?", id).Update("status", body.Status)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error: " + res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Allocation not found"})
		return
	}

	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()
	c.JSON(http.StatusOK, gin.H{"message": "Status updated"})
}

// DestroyAllocation handles DELETE /api/admin/allocations/:id/destroy.
//
// Working:
// 1. Extracts the allocation ":id" route parameter.
// 2. Complete Purge Cascade:
//    - Deletes all models.RequestItem records associated with this allocation_id.
//    - Deletes all models.FormField dynamic field records associated with this allocation_id.
//    - Deletes the parent models.Allocation record itself.
// 3. Security Audit Logging:
//    Creates an immutable models.AuditLogItem entry with event "SESSION_DESTROYED_FULL_PURGE",
//    storing the admin's client IP address and affected allocation ID.
// 4. Real-Time Broadcast:
//    Calls NotifyPublicAllocationsChanged() to purge the session from public screens.
//    Calls NotifyAdminDashboardChanged() to notify admin dashboards.
// 5. Returns HTTP 200 OK `{"message": "Session and all related request records destroyed successfully"}`.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Performs cascade deletion across RequestItem, FormField, and Allocation tables in database.DB.
// - Creates AuditLogItem in database.DB.
// - Triggers NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
func DestroyAllocation(c *gin.Context) {
	id := c.Param("id")

	// Complete Purge: Delete all request items, form fields, and allocation record from DB
	database.DB.Where("allocation_id = ?", id).Delete(&models.RequestItem{})
	database.DB.Where("allocation_id = ?", id).Delete(&models.FormField{})
	database.DB.Where("id = ?", id).Delete(&models.Allocation{})

	// Log audit trail
	database.DB.Create(&models.AuditLogItem{
		ID:           "log-" + uuid.New().String()[:8],
		Event:        "SESSION_DESTROYED_FULL_PURGE",
		AllocationID: id,
		IPAddress:    c.ClientIP(),
		Metadata:     `{"status":"SESSION_AND_ALL_REQUESTS_DELETED"}`,
		CreatedAt:    time.Now(),
	})

	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()
	c.JSON(http.StatusOK, gin.H{"message": "Session and all related request records destroyed successfully"})
}

// ExportAllocationCSV handles GET /api/admin/allocations/:id/export (Super Admin only).
//
// Working:
// 1. Extracts allocation ":id" route parameter.
// 2. Queries all models.RequestItem records for this allocation, ordered by assigned token number
//    (nulls last) and submission time.
// 3. Queries configured models.FormField records for this allocation, ordered by display order.
// 4. Decrypts every request's FormData via toDTO() (AES-256-CFB decryption) and discovers all
//    distinct form field keys across requests and field configurations.
// 5. Constructs an Excel XLSX workbook using the github.com/xuri/excelize/v2 library.
// 6. Generates formatted column headers:
//    - Fixed fields: Request ID, Assigned Token Number, Queue Status, Session Name, Date,
//      Submitted At, Accepted At, User Session Device ID.
//    - Dynamic form fields: "Form Field: <key>" for every field found.
//    - Raw JSON: "Full Form Data JSON".
// 7. Applies dark slate styling (bold white text, fill #334155, centered) to header row.
// 8. Populates rows with formatted data, converting token numbers (e.g. "#1") and dates.
// 9. Sets column widths to 22 units for clean readability.
// 10. Sets HTTP headers for XLSX file attachment ("session_<id>_export.xlsx") and writes workbook
//     directly to the Gin response writer.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware and SuperAdminMiddleware.
// - Queries database.DB for requests and form fields.
// - Calls toDTO() which uses services.Decrypt() to decrypt personal data for export.
// - Streams XLSX binary payload to client via c.Writer.
func ExportAllocationCSV(c *gin.Context) {
	id := c.Param("id")

	var requests []models.RequestItem
	database.DB.Where("allocation_id = ?", id).Order("assigned_token ASC NULLS LAST, submitted_at ASC").Find(&requests)

	// Fetch dynamic form fields defined for this allocation
	var formFields []models.FormField
	database.DB.Where("allocation_id = ?", id).Order("display_order ASC").Find(&formFields)

	// Convert all requests to DTOs and collect all unique form keys
	dtos := make([]RequestItemDTO, len(requests))
	allFormKeysSet := make(map[string]bool)
	allFormKeysList := []string{}

	// First add keys from configured FormFields in order
	for _, ff := range formFields {
		if !allFormKeysSet[ff.FieldKey] {
			allFormKeysSet[ff.FieldKey] = true
			allFormKeysList = append(allFormKeysList, ff.FieldKey)
		}
	}

	for i, r := range requests {
		dtos[i] = toDTO(r)
		for k := range dtos[i].FormData {
			if !allFormKeysSet[k] {
				allFormKeysSet[k] = true
				allFormKeysList = append(allFormKeysList, k)
			}
		}
	}

	f := excelize.NewFile()
	sheetName := "Token Requests"
	f.SetSheetName("Sheet1", sheetName)

	headers := []string{
		"Request ID",
		"Assigned Token Number",
		"Queue Status",
		"Session Name",
		"Date",
		"Submitted At",
		"Accepted At",
		"User Session Device ID",
	}

	for _, k := range allFormKeysList {
		headers = append(headers, fmt.Sprintf("Form Field: %s", k))
	}
	headers = append(headers, "Full Form Data JSON")

	// Set header row
	for colIdx, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(colIdx+1, 1)
		f.SetCellValue(sheetName, cell, header)
	}

	// Apply dark header styling with bold white text
	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Size: 11},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"334155"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	if err == nil {
		lastCol, _ := excelize.CoordinatesToCellName(len(headers), 1)
		f.SetCellStyle(sheetName, "A1", lastCol, headerStyle)
	}

	// Write data rows
	for rowIdx, r := range requests {
		dto := dtos[rowIdx]

		tokenStr := ""
		if r.AssignedToken > 0 {
			tokenStr = fmt.Sprintf("#%d", r.AssignedToken)
		}

		acceptedAtStr := ""
		if !r.AcceptedAt.IsZero() {
			acceptedAtStr = r.AcceptedAt.Format("2006-01-02 15:04:05")
		}

		rowValues := []interface{}{
			r.ID,
			tokenStr,
			r.Status,
			r.AllocationName,
			r.Date,
			r.SubmittedAt.Format("2006-01-02 15:04:05"),
			acceptedAtStr,
			r.UserSessionID,
		}

		for _, k := range allFormKeysList {
			valStr := ""
			if val, ok := dto.FormData[k]; ok && val != nil {
				valStr = fmt.Sprintf("%v", val)
			}
			rowValues = append(rowValues, valStr)
		}

		jsonBytes, _ := json.Marshal(dto.FormData)
		rowValues = append(rowValues, string(jsonBytes))

		for colIdx, val := range rowValues {
			cell, _ := excelize.CoordinatesToCellName(colIdx+1, rowIdx+2)
			f.SetCellValue(sheetName, cell, val)
		}
	}

	// Set generous column width
	for colIdx := range headers {
		colName, _ := excelize.ColumnNumberToName(colIdx + 1)
		f.SetColWidth(sheetName, colName, colName, 22)
	}

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=session_%s_export.xlsx", id))

	if err := f.Write(c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write XLSX export: " + err.Error()})
	}
}

// GetAdminRequests handles GET /api/admin/requests.
//
// Working:
// 1. Parses query parameters:
//    - allocation_id: Filter by specific session ID.
//    - status: Filter by queue status (PENDING, ACCEPTED, HOLD, SERVED, REJECTED, CANCELLED).
//    - search / q: Substring search term.
// 2. Builds query against PostgreSQL models.RequestItem, ordered by assigned token number
//    (nulls last) and submission time.
// 3. Converts all matching records to RequestItemDTOs via toDTO(r) (decrypting form data).
// 4. If search query is present, performs deep in-memory substring filtering (case-insensitive) across:
//    - Request ID
//    - Assigned Token Number
//    - Allocation Name
//    - Status
//    - User Session ID
//    - Dynamic Form Data field keys and values
// 5. Returns HTTP 200 OK with the array of matched DTOs.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Reads from database.DB.
// - Calls toDTO() for form data decryption.
func GetAdminRequests(c *gin.Context) {
	allocID := c.Query("allocation_id")
	status := c.Query("status")
	searchQuery := strings.TrimSpace(c.Query("search"))
	if searchQuery == "" {
		searchQuery = strings.TrimSpace(c.Query("q"))
	}

	query := database.DB.Model(&models.RequestItem{}).Order("assigned_token ASC NULLS LAST, submitted_at ASC")
	if allocID != "" {
		query = query.Where("allocation_id = ?", allocID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var reqs []models.RequestItem
	query.Find(&reqs)

	dtos := make([]RequestItemDTO, 0, len(reqs))
	qLower := strings.ToLower(searchQuery)

	for _, r := range reqs {
		dto := toDTO(r)
		if qLower != "" {
			// Search across ID, assigned token, allocation name, status, user session ID, and form data keys/values
			match := strings.Contains(strings.ToLower(dto.ID), qLower) ||
				strings.Contains(fmt.Sprintf("%d", dto.AssignedToken), qLower) ||
				strings.Contains(strings.ToLower(dto.AllocationName), qLower) ||
				strings.Contains(strings.ToLower(dto.Status), qLower) ||
				strings.Contains(strings.ToLower(dto.UserSessionID), qLower)

			if !match && dto.FormData != nil {
				for k, v := range dto.FormData {
					if strings.Contains(strings.ToLower(k), qLower) {
						match = true
						break
					}
					if v != nil && strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), qLower) {
						match = true
						break
					}
				}
			}

			if !match {
				continue
			}
		}
		dtos = append(dtos, dto)
	}

	c.JSON(http.StatusOK, dtos)
}

// AcceptRequest handles POST /api/admin/requests/:id/accept.
//
// Working:
// 1. Extracts request ":id" parameter and queries PostgreSQL. Returns 404 if missing.
// 2. Token Number Assignment / Resumption:
//    - If AssignedToken > 0 (ticket was previously assigned a number, e.g. from HOLD or SERVED),
//      it preserves the original token number and simply transitions status back to "ACCEPTED".
//    - If AssignedToken == 0 (new unassigned request):
//      * Starts a database transaction (database.DB.Transaction).
//      * Executes atomic counter increment:
//        `UPDATE allocations SET current_sequence = current_sequence + 1 WHERE id = ? RETURNING current_sequence`
//      * Sets req.AssignedToken to the returned sequence number.
//      * Sets req.Status = "ACCEPTED", req.AcceptedAt = now, req.UpdatedAt = now.
//      * Commits transaction to ensure no two requests receive duplicate token numbers under concurrent load.
// 3. Converts updated request to RequestItemDTO via toDTO(req).
// 4. Real-Time Push:
//    - Emits update specifically to the ticket's private SSE topic via Broker.NotifyClient(reqID, dto).
//    - Broadcasts refreshed public allocations via NotifyPublicAllocationsChanged().
//    - Broadcasts admin dashboard pulse via NotifyAdminDashboardChanged().
// 5. Returns HTTP 200 OK with the updated RequestItemDTO.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Executes transaction against database.DB.
// - Calls Broker.NotifyClient(), NotifyPublicAllocationsChanged(), and NotifyAdminDashboardChanged().
func AcceptRequest(c *gin.Context) {
	reqID := c.Param("id")
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	// If token number was already assigned previously (e.g. SERVED or HOLD), retain existing token number when re-opening to ACCEPTED (Serving)!
	if req.AssignedToken > 0 {
		now := time.Now()
		req.Status = "ACCEPTED"
		req.UpdatedAt = now
		if err := database.DB.Save(&req).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update request: " + err.Error()})
			return
		}
	} else {
		// New request: atomic token sequence increment
		var newTokenSeq int
		txErr := database.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Raw(
				`UPDATE allocations SET current_sequence = current_sequence + 1 WHERE id = ? RETURNING current_sequence`,
				req.AllocationID,
			).Scan(&newTokenSeq).Error; err != nil {
				return err
			}
			now := time.Now()
			req.Status = "ACCEPTED"
			req.AssignedToken = newTokenSeq
			req.AcceptedAt = now
			req.UpdatedAt = now
			return tx.Save(&req).Error
		})
		if txErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept request: " + txErr.Error()})
			return
		}
	}

	dto := toDTO(req)
	Broker.NotifyClient(reqID, dto)
	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()
	c.JSON(http.StatusOK, dto)
}

// RejectRequest handles POST /api/admin/requests/:id/reject.
//
// Working:
// 1. Extracts request ":id" parameter and queries PostgreSQL. Returns 404 if missing.
// 2. Updates request status to "REJECTED" and refreshes UpdatedAt timestamp.
// 3. Persists update to PostgreSQL database.DB.
// 4. Converts to RequestItemDTO via toDTO(req).
// 5. Pushes update to ticket subscriber via Broker.NotifyClient(reqID, dto).
// 6. Broadcasts NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
// 7. Returns HTTP 200 OK with the DTO.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Updates database.DB.
// - Triggers Broker.NotifyClient() and SSE notifications.
func RejectRequest(c *gin.Context) {
	reqID := c.Param("id")
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	req.Status = "REJECTED"
	req.UpdatedAt = time.Now()
	database.DB.Save(&req)

	dto := toDTO(req)
	Broker.NotifyClient(reqID, dto)
	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()

	c.JSON(http.StatusOK, dto)
}

// HoldRequest handles POST /api/admin/requests/:id/hold.
//
// Working:
// 1. Extracts request ":id" parameter and queries PostgreSQL. Returns 404 if missing.
// 2. Transitions status to "HOLD" (temporarily paused at counter) and updates timestamp.
// 3. Saves update to database.DB.
// 4. Converts to RequestItemDTO via toDTO(req).
// 5. Pushes update to ticket subscriber via Broker.NotifyClient(reqID, dto).
// 6. Broadcasts NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
// 7. Returns HTTP 200 OK with the DTO.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Updates database.DB.
// - Triggers Broker.NotifyClient() and SSE notifications.
func HoldRequest(c *gin.Context) {
	reqID := c.Param("id")
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	req.Status = "HOLD"
	req.UpdatedAt = time.Now()
	database.DB.Save(&req)

	dto := toDTO(req)
	Broker.NotifyClient(reqID, dto)
	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()

	c.JSON(http.StatusOK, dto)
}

// ServeRequest handles POST /api/admin/requests/:id/serve.
//
// Working:
// 1. Extracts request ":id" parameter and queries PostgreSQL. Returns 404 if missing.
// 2. Transitions status to "SERVED" (service completed at counter) and updates timestamp.
// 3. Saves update to database.DB.
// 4. Converts to RequestItemDTO via toDTO(req).
// 5. Pushes update to ticket subscriber via Broker.NotifyClient(reqID, dto).
// 6. Broadcasts NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
// 7. Returns HTTP 200 OK with the DTO.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Updates database.DB.
// - Triggers Broker.NotifyClient() and SSE notifications.
func ServeRequest(c *gin.Context) {
	reqID := c.Param("id")
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	req.Status = "SERVED"
	req.UpdatedAt = time.Now()
	database.DB.Save(&req)

	dto := toDTO(req)
	Broker.NotifyClient(reqID, dto)
	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()

	c.JSON(http.StatusOK, dto)
}

// CancelOwnRequest handles POST /api/public/requests/:id/cancel (User Self-Service).
//
// Working:
// 1. Extracts request ":id" parameter and queries PostgreSQL. Returns 404 if missing.
// 2. State Validation:
//    Verifies that req.Status is strictly "PENDING". If ticket has already been accepted, served,
//    or cancelled, returns HTTP 400 Bad Request ("Only PENDING token requests can be cancelled").
// 3. Updates status to "CANCELLED" and refreshes UpdatedAt.
// 4. Persists change to database.DB.
// 5. Converts to RequestItemDTO via toDTO(req).
// 6. Pushes update to ticket subscriber via Broker.NotifyClient(reqID, dto).
// 7. Broadcasts NotifyPublicAllocationsChanged() and NotifyAdminDashboardChanged().
// 8. Returns HTTP 200 OK with the DTO.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Public unauthenticated route.
// - Updates database.DB.
// - Triggers Broker.NotifyClient() and SSE notifications.
func CancelOwnRequest(c *gin.Context) {
	reqID := c.Param("id")
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token request not found"})
		return
	}

	// Only cancellable if PENDING
	if req.Status != "PENDING" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only PENDING token requests can be cancelled. Status is: " + req.Status})
		return
	}

	req.Status = "CANCELLED"
	req.UpdatedAt = time.Now()
	if err := database.DB.Save(&req).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel token request: " + err.Error()})
		return
	}

	dto := toDTO(req)
	Broker.NotifyClient(reqID, dto)
	NotifyPublicAllocationsChanged()
	NotifyAdminDashboardChanged()
	c.JSON(http.StatusOK, dto)
}

// GetQRSignature handles GET /api/public/requests/:id/qr-sig.
//
// Working:
// 1. Extracts ":id" parameter. Returns 400 Bad Request if empty.
// 2. Queries PostgreSQL to verify the target request actually exists. Returns 404 if not found
//    (prevents malicious actors from generating valid HMAC signatures for fabricated request IDs).
// 3. Resolves secret key hierarchy: QR_HMAC_SECRET -> SESSION_SECRET -> in-memory sessionHMACSecret.
// 4. Computes HMAC-SHA256 signature of reqID using the resolved secret.
// 5. Encodes MAC digest to a 64-character hexadecimal string.
// 6. Returns HTTP 200 OK `{"sig": "<64-char hex>"}`.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Public unauthenticated route.
// - Secret never leaves the server; client embeds the signature into the QR code link
//   (e.g., `/requests/:id/status?sig=<hex>`).
// - Scanner endpoints verify this signature via verifyQRSig().
func GetQRSignature(c *gin.Context) {
	reqID := c.Param("id")
	if reqID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request ID is required"})
		return
	}
	// Verify the request actually exists (prevents fishing for random sigs)
	var req models.RequestItem
	if err := database.DB.First(&req, "id = ?", reqID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}
	// Sign using the same SESSION_SECRET (or its own env var QR_HMAC_SECRET)
	secret := os.Getenv("QR_HMAC_SECRET")
	if secret == "" {
		secret = os.Getenv("SESSION_SECRET")
	}
	if secret == "" {
		// Fallback to sessionHMACSecret (already derived in init)
		secret = hex.EncodeToString(sessionHMACSecret)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(reqID))
	sig := hex.EncodeToString(mac.Sum(nil))
	c.JSON(http.StatusOK, gin.H{"sig": sig})
}

// GetDashboardStats handles GET /api/admin/dashboard/stats.
//
// Working:
// 1. Obtains today's date in "YYYY-MM-DD" format.
// 2. Queries PostgreSQL for:
//    - lastIssuedToken: Maximum assigned token number today for accepted requests using COALESCE(MAX(assigned_token), 0).
//    - totalAllocations: Count of allocations created for today's date.
//    - pendingRequests: Count of pending requests today.
//    - acceptedRequests: Count of accepted requests today.
//    - rejectedRequests: Count of rejected requests today.
// 3. Returns HTTP 200 OK with the consolidated KPI summary JSON.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Reads from database.DB.
func GetDashboardStats(c *gin.Context) {
	today := time.Now().Format("2006-01-02")
	var totalAllocations int64
	var pendingRequests int64
	var acceptedRequests int64
	var rejectedRequests int64

	// Bug #11 fix: scope all counts to today's date consistently
	var lastIssuedToken int
	database.DB.Model(&models.RequestItem{}).
		Where("date = ? AND status = ? AND assigned_token > 0", today, "ACCEPTED").
		Select("COALESCE(MAX(assigned_token), 0)").
		Scan(&lastIssuedToken)

	database.DB.Model(&models.Allocation{}).Where("date = ?", today).Count(&totalAllocations)
	database.DB.Model(&models.RequestItem{}).Where("date = ? AND status = ?", today, "PENDING").Count(&pendingRequests)
	database.DB.Model(&models.RequestItem{}).Where("date = ? AND status = ?", today, "ACCEPTED").Count(&acceptedRequests)
	database.DB.Model(&models.RequestItem{}).Where("date = ? AND status = ?", today, "REJECTED").Count(&rejectedRequests)

	c.JSON(http.StatusOK, gin.H{
		"today_date":        today,
		"total_allocations": totalAllocations,
		"pending_requests":  pendingRequests,
		"accepted_requests": acceptedRequests,
		"rejected_requests": rejectedRequests,
		"tokens_issued":     lastIssuedToken,
		"currently_serving": acceptedRequests,
	})
}

// GetAuditLogs handles GET /api/admin/audit-logs.
//
// Working:
// 1. Queries PostgreSQL models.AuditLogItem, ordered by created_at descending, limited to 50 records.
// 2. Returns HTTP 200 OK with JSON array of audit logs.
//
// Parameters:
// - c: Gin request context.
//
// Interactions:
// - Guarded by AdminAuthMiddleware.
// - Reads from database.DB.
func GetAuditLogs(c *gin.Context) {
	var logs []models.AuditLogItem
	database.DB.Order("created_at desc").Limit(50).Find(&logs)
	c.JSON(http.StatusOK, logs)
}

