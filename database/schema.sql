-- Database: token_alloc_db

DROP TABLE IF EXISTS request_items CASCADE;
DROP TABLE IF EXISTS form_fields CASCADE;
DROP TABLE IF EXISTS allocations CASCADE;
DROP TABLE IF EXISTS admins CASCADE;
DROP TABLE IF EXISTS audit_log_items CASCADE;

-- Table: allocations
CREATE TABLE allocations (
    id VARCHAR(255) PRIMARY KEY,
    date VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    opening_time VARCHAR(50) NOT NULL,
    closing_time VARCHAR(50) NOT NULL,
    max_tokens INTEGER,
    additional_instructions TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    current_sequence INTEGER DEFAULT 0,
    waiting_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table: form_fields
CREATE TABLE form_fields (
    id VARCHAR(255) PRIMARY KEY,
    allocation_id VARCHAR(255) NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
    field_key VARCHAR(100) NOT NULL,
    label VARCHAR(255) NOT NULL,
    field_type VARCHAR(50) NOT NULL,
    required BOOLEAN DEFAULT false,
    options TEXT, -- JSON string
    display_order INTEGER NOT NULL DEFAULT 1
);

-- Table: request_items
CREATE TABLE request_items (
    id VARCHAR(255) PRIMARY KEY,
    allocation_id VARCHAR(255) NOT NULL REFERENCES allocations(id) ON DELETE CASCADE,
    allocation_name VARCHAR(255) NOT NULL,
    date VARCHAR(50) NOT NULL,
    user_session_id VARCHAR(255) NOT NULL,
    form_data TEXT NOT NULL, -- Encrypted AES-256 JSON string
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    assigned_token INTEGER,
    queue_position INTEGER NOT NULL DEFAULT 0,
    estimated_wait INTEGER NOT NULL DEFAULT 0,
    idempotency_key VARCHAR(255),
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    accepted_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table: admins
CREATE TABLE admins (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, -- Hashed
    role VARCHAR(32) NOT NULL DEFAULT 'ADMIN',
    session_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table: audit_log_items
CREATE TABLE audit_log_items (
    id VARCHAR(255) PRIMARY KEY,
    event VARCHAR(255) NOT NULL,
    admin_id VARCHAR(255),
    request_id VARCHAR(255),
    allocation_id VARCHAR(255),
    ip_address VARCHAR(100) NOT NULL,
    metadata TEXT, -- JSON string
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);