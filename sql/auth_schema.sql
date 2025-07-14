-- =========================================
-- AUTHENTICATION & AUTHORIZATION SCHEMA
-- Complete schema with customer auth support
-- =========================================

-- User_Role Table
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
    INDEX idx_expires_at (expires_at),
    INDEX idx_active_rate_limit (active, rate_limit_per_hour)
);

-- API_Key_Usage_Log Table
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
    INDEX idx_response_status (response_status),
    INDEX idx_api_usage_key_time (api_key_id, created_at),
    INDEX idx_api_usage_time_status (created_at, response_status)
);

-- System_Log Table
CREATE TABLE System_Log (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_level ENUM('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL') NOT NULL,
    component VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_log_level (log_level),
    INDEX idx_component (component),
    INDEX idx_created_at (created_at)
);

-- =========================================
-- RATE LIMITING VIEWS AND PROCEDURES
-- =========================================

-- View for API Key Usage in Last Hour
CREATE VIEW API_Key_Usage_Last_Hour AS
SELECT
    ak.api_key_id,
    ak.key_name,
    ak.key_prefix,
    ak.rate_limit_per_hour,
    ak.active,
    COUNT(ul.log_id) as usage_last_hour,
    ak.rate_limit_per_hour - COUNT(ul.log_id) as remaining_requests,
    CASE
        WHEN COUNT(ul.log_id) >= ak.rate_limit_per_hour THEN TRUE
        ELSE FALSE
    END as is_rate_limited,
    CASE
        WHEN COUNT(ul.log_id) >= ak.rate_limit_per_hour * 0.9 THEN TRUE
        ELSE FALSE
    END as approaching_limit,
    MAX(ul.created_at) as last_request_time
FROM API_Key ak
LEFT JOIN API_Key_Usage_Log ul ON ak.api_key_id = ul.api_key_id
    AND ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
WHERE ak.active = TRUE
GROUP BY ak.api_key_id, ak.key_name, ak.key_prefix, ak.rate_limit_per_hour, ak.active;

-- View for API Key Usage Statistics
CREATE VIEW API_Key_Usage_Stats AS
SELECT
    ak.api_key_id,
    ak.key_name,
    ak.key_prefix,
    ak.rate_limit_per_hour,
    ak.active,
    ak.created_at as key_created,
    ak.last_used,
    ak.usage_count,

    -- Usage in different time periods
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as usage_last_hour,
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as usage_last_24h,
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as usage_last_7d,
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as usage_last_30d,

    -- Success/Error rates
    COUNT(CASE WHEN ul.response_status >= 200 AND ul.response_status < 300 THEN 1 END) as successful_requests,
    COUNT(CASE WHEN ul.response_status >= 400 THEN 1 END) as error_requests,
    COUNT(CASE WHEN ul.response_status = 429 THEN 1 END) as rate_limited_requests,

    -- Performance metrics
    AVG(ul.response_time_ms) as avg_response_time_ms,
    MAX(ul.response_time_ms) as max_response_time_ms,
    MIN(ul.response_time_ms) as min_response_time_ms,

    -- Rate limiting status
    ak.rate_limit_per_hour - COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as remaining_requests_this_hour,
    CASE
        WHEN COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) >= ak.rate_limit_per_hour THEN TRUE
        ELSE FALSE
    END as currently_rate_limited,

    -- Most recent activity
    MAX(ul.created_at) as last_request_time,
    COUNT(DISTINCT DATE(ul.created_at)) as active_days,

    -- Creator info
    creator.username as created_by_username

FROM API_Key ak
LEFT JOIN API_Key_Usage_Log ul ON ak.api_key_id = ul.api_key_id
LEFT JOIN System_User creator ON ak.created_by = creator.user_id
GROUP BY ak.api_key_id, ak.key_name, ak.key_prefix, ak.rate_limit_per_hour,
         ak.active, ak.created_at, ak.last_used, ak.usage_count, creator.username;

-- =========================================
-- STORED PROCEDURES
-- =========================================

DELIMITER //

-- Procedure to check if API key can make a request
CREATE PROCEDURE CheckAPIKeyRateLimit(
    IN p_api_key_id INT,
    OUT p_can_proceed BOOLEAN,
    OUT p_usage_count INT,
    OUT p_rate_limit INT,
    OUT p_remaining INT
)
BEGIN
    DECLARE v_usage_last_hour INT DEFAULT 0;
    DECLARE v_rate_limit_per_hour INT DEFAULT 1000;

    -- Get the API key's rate limit
    SELECT rate_limit_per_hour
    INTO v_rate_limit_per_hour
    FROM API_Key
    WHERE api_key_id = p_api_key_id AND active = TRUE;

    -- Get usage in the last hour
    SELECT COUNT(*)
    INTO v_usage_last_hour
    FROM API_Key_Usage_Log
    WHERE api_key_id = p_api_key_id
    AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);

    -- Set output parameters
    SET p_usage_count = v_usage_last_hour;
    SET p_rate_limit = v_rate_limit_per_hour;
    SET p_remaining = v_rate_limit_per_hour - v_usage_last_hour;
    SET p_can_proceed = (v_usage_last_hour < v_rate_limit_per_hour);
END //

-- Procedure to get rate limiting info for all API keys
CREATE PROCEDURE GetAllAPIKeyRateLimitStatus()
BEGIN
    SELECT
        ak.api_key_id,
        ak.key_name,
        ak.key_prefix,
        ak.rate_limit_per_hour,
        ak.active,
        COALESCE(usage_stats.usage_last_hour, 0) as usage_last_hour,
        ak.rate_limit_per_hour - COALESCE(usage_stats.usage_last_hour, 0) as remaining_requests,
        CASE
            WHEN COALESCE(usage_stats.usage_last_hour, 0) >= ak.rate_limit_per_hour THEN 'RATE_LIMITED'
            WHEN COALESCE(usage_stats.usage_last_hour, 0) >= ak.rate_limit_per_hour * 0.9 THEN 'APPROACHING_LIMIT'
            WHEN COALESCE(usage_stats.usage_last_hour, 0) >= ak.rate_limit_per_hour * 0.5 THEN 'MODERATE_USAGE'
            ELSE 'LOW_USAGE'
        END as status,
        COALESCE(usage_stats.last_request_time, NULL) as last_request_time,
        ak.last_used,
        ak.usage_count as total_usage_count,
        creator.username as created_by_username
    FROM API_Key ak
    LEFT JOIN (
        SELECT
            api_key_id,
            COUNT(*) as usage_last_hour,
            MAX(created_at) as last_request_time
        FROM API_Key_Usage_Log
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY api_key_id
    ) usage_stats ON ak.api_key_id = usage_stats.api_key_id
    LEFT JOIN System_User creator ON ak.created_by = creator.user_id
    WHERE ak.active = TRUE
    ORDER BY usage_stats.usage_last_hour DESC, ak.key_name;
END //

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

-- Procedure to clean up old rate limiting data (run daily)
CREATE PROCEDURE CleanupRateLimitingData()
BEGIN
    DECLARE v_deleted_logs INT DEFAULT 0;

    -- Delete API usage logs older than 90 days
    DELETE FROM API_Key_Usage_Log
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);

    -- Get count of deleted records
    SET v_deleted_logs = ROW_COUNT();

    -- Log the cleanup operation
    INSERT INTO System_Log (log_level, component, message, metadata, created_at)
    VALUES (
        'INFO',
        'RATE_LIMITING',
        'Cleaned up old API usage logs',
        JSON_OBJECT('deleted_records', v_deleted_logs),
        NOW()
    );
END //

DELIMITER ;

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
        'logs', JSON_ARRAY('read'),
        'roles', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'service_tiers', JSON_ARRAY('create', 'read', 'update', 'delete')
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
        'logs', JSON_ARRAY('read'),
        'roles', JSON_ARRAY('read'),
        'service_tiers', JSON_ARRAY('read')
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
    '$2a$12$8vJ.QGH5gKqY5vJ.QGH5gOqJ8vJ.QGH5gKqY5vJ.QGH5gOqJ8vJ.QG',
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
    '$2a$12$7uI.PGH5fJpX4uI.PGH5fNpI7uI.PGH5fJpX4uI.PGH5fNpI7uI.PF',
    ur.role_id,
    'System',
    'Viewer',
    TRUE,
    su.user_id
FROM User_Role ur, System_User su
WHERE ur.name = 'viewer' AND su.username = 'admin';

-- =========================================
-- CREATE SCHEDULED EVENTS FOR CLEANUP
-- =========================================

CREATE EVENT IF NOT EXISTS CleanExpiredSessionsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanExpiredSessions();

CREATE EVENT IF NOT EXISTS CleanOldAPILogsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanOldAPILogs();

CREATE EVENT IF NOT EXISTS RateLimitingCleanupEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanupRateLimitingData();
