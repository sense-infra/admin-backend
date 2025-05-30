-- =========================================
-- AUTHENTICATION & AUTHORIZATION SCHEMA
-- Add to existing schema for user management and API keys
-- =========================================

-- User_Role Table
-- Purpose: Define system roles with permissions
CREATE TABLE User_Role (
    role_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the role',
    name VARCHAR(50) NOT NULL UNIQUE COMMENT 'Role name (admin, viewer)',
    description TEXT COMMENT 'Role description and permissions',
    permissions JSON NOT NULL COMMENT 'JSON object defining permissions (create, read, update, delete, manage_api_keys, etc.)',
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether this role is active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- System_User Table
-- Purpose: Stores system users (admin, viewer, etc.)
CREATE TABLE System_User (
    user_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the user',
    username VARCHAR(50) NOT NULL UNIQUE COMMENT 'Username for login',
    email VARCHAR(255) NOT NULL UNIQUE COMMENT 'User email address',
    password_hash VARCHAR(255) NOT NULL COMMENT 'Bcrypt hashed password',
    role_id INT NOT NULL COMMENT 'Reference to user role',
    first_name VARCHAR(100) COMMENT 'User first name',
    last_name VARCHAR(100) COMMENT 'User last name',
    
    -- Security fields
    force_password_change BOOLEAN DEFAULT TRUE COMMENT 'Force password change on next login',
    last_login TIMESTAMP NULL COMMENT 'Last successful login timestamp',
    failed_login_attempts INT DEFAULT 0 COMMENT 'Number of consecutive failed login attempts',
    locked_until TIMESTAMP NULL COMMENT 'Account locked until this timestamp',
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When password was last changed',
    
    -- Account status
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether user account is active',
    created_by INT COMMENT 'User ID who created this account',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (role_id) REFERENCES User_Role(role_id),
    FOREIGN KEY (created_by) REFERENCES System_User(user_id),
    
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_role (role_id),
    INDEX idx_active (active)
);

-- User_Session Table
-- Purpose: Manage user sessions and JWT tokens
CREATE TABLE User_Session (
    session_id VARCHAR(255) PRIMARY KEY COMMENT 'Unique session identifier (JWT jti)',
    user_id INT NOT NULL COMMENT 'Reference to the user',
    token_hash VARCHAR(255) NOT NULL COMMENT 'SHA256 hash of the JWT token',
    ip_address VARCHAR(45) COMMENT 'IP address of the session',
    user_agent TEXT COMMENT 'User agent string',
    expires_at TIMESTAMP NOT NULL COMMENT 'When the session expires',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES System_User(user_id),
    
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_token_hash (token_hash)
);

-- API_Key Table
-- Purpose: Manage API keys for external access (moved from config to DB)
CREATE TABLE API_Key (
    api_key_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the API key',
    key_name VARCHAR(100) NOT NULL COMMENT 'Human-readable name for the API key',
    key_hash VARCHAR(255) NOT NULL UNIQUE COMMENT 'SHA256 hash of the API key',
    key_prefix VARCHAR(20) NOT NULL COMMENT 'First few characters of key for identification',
    
    -- Permissions and scope
    permissions JSON NOT NULL COMMENT 'JSON object defining API permissions',
    contract_access JSON COMMENT 'JSON array of contract IDs this key can access (NULL = all)',
    rate_limit_per_hour INT DEFAULT 1000 COMMENT 'API calls per hour limit',
    
    -- Key metadata
    created_by INT NOT NULL COMMENT 'User who created this API key',
    description TEXT COMMENT 'Description of API key usage',
    
    -- Security and status
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether the API key is active',
    last_used TIMESTAMP NULL COMMENT 'Last time this API key was used',
    usage_count BIGINT DEFAULT 0 COMMENT 'Total number of API calls made',
    
    -- Expiration
    expires_at TIMESTAMP NULL COMMENT 'When the API key expires (NULL = no expiration)',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (created_by) REFERENCES System_User(user_id),
    
    INDEX idx_key_hash (key_hash),
    INDEX idx_key_prefix (key_prefix),
    INDEX idx_created_by (created_by),
    INDEX idx_active (active),
    INDEX idx_expires_at (expires_at)
);

-- API_Key_Usage_Log Table
-- Purpose: Log API key usage for monitoring and analytics
CREATE TABLE API_Key_Usage_Log (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the log entry',
    api_key_id INT NOT NULL COMMENT 'Reference to the API key used',
    endpoint VARCHAR(255) NOT NULL COMMENT 'API endpoint called',
    method ENUM('GET', 'POST', 'PUT', 'DELETE', 'PATCH') NOT NULL COMMENT 'HTTP method',
    ip_address VARCHAR(45) COMMENT 'IP address of the request',
    user_agent TEXT COMMENT 'User agent string',
    response_status INT COMMENT 'HTTP response status code',
    response_time_ms INT COMMENT 'Response time in milliseconds',
    request_size_bytes INT COMMENT 'Size of request in bytes',
    response_size_bytes INT COMMENT 'Size of response in bytes',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (api_key_id) REFERENCES API_Key(api_key_id),
    
    INDEX idx_api_key_id (api_key_id),
    INDEX idx_created_at (created_at),
    INDEX idx_endpoint (endpoint),
    INDEX idx_response_status (response_status)
);

-- =========================================
-- INSERT DEFAULT ROLES
-- =========================================

INSERT INTO User_Role (name, description, permissions) VALUES 
(
    'admin',
    'Administrator with full system access',
    JSON_OBJECT(
        'users', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'contracts', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'customers', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'controllers', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'cameras', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'events', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'api_keys', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'rf_monitoring', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'system_config', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'logs', JSON_ARRAY('read')
    )
),
(
    'viewer',
    'Read-only access to system data',
    JSON_OBJECT(
        'users', JSON_ARRAY('read'),
        'contracts', JSON_ARRAY('read'),
        'customers', JSON_ARRAY('read'),
        'controllers', JSON_ARRAY('read'),
        'cameras', JSON_ARRAY('read'),
        'events', JSON_ARRAY('read'),
        'api_keys', JSON_ARRAY('read'),
        'rf_monitoring', JSON_ARRAY('read'),
        'system_config', JSON_ARRAY('read'),
        'logs', JSON_ARRAY('read')
    )
);

-- =========================================
-- INSERT DEFAULT ADMIN USER
-- =========================================
-- Default password: "SenseGuard2025!" (should be changed on first login)
-- Password hash generated with bcrypt cost 12

INSERT INTO System_User (username, email, password_hash, role_id, first_name, last_name, force_password_change) 
SELECT 
    'admin',
    'admin@senseguard.local',
    '$2b$12$DF0N9s4/elrEhQzUnuzrtuwK6JGK.XhV85xTfMRve15KH/y6u.bQu',
    role_id,
    'System',
    'Administrator',
    TRUE
FROM User_Role WHERE name = 'admin';

-- Insert default viewer user
-- Default password: "Viewer2025!" (should be changed on first login)

INSERT INTO System_User (username, email, password_hash, role_id, first_name, last_name, force_password_change, created_by) 
SELECT 
    'viewer',
    'viewer@senseguard.local',
    '$2b$12$1402BMPyDy21zXijntLhIe.GHV1CeMulgMOM4eILlRM1zC1PlJCti',
    ur.role_id,
    'System',
    'Viewer',
    TRUE,
    su.user_id
FROM User_Role ur, System_User su 
WHERE ur.name = 'viewer' AND su.username = 'admin';

-- =========================================
-- CLEANUP PROCEDURES
-- =========================================

DELIMITER //

-- Procedure to clean expired sessions
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    DELETE FROM User_Session WHERE expires_at < NOW();
END //

-- Procedure to clean old API usage logs (keep 90 days)
CREATE PROCEDURE CleanOldAPILogs()
BEGIN
    DELETE FROM API_Key_Usage_Log WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
END //

DELIMITER ;

-- Create events to run cleanup procedures daily
CREATE EVENT IF NOT EXISTS CleanExpiredSessionsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanExpiredSessions();

CREATE EVENT IF NOT EXISTS CleanOldAPILogsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanOldAPILogs();
