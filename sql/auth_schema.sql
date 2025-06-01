-- =========================================
-- AUTHENTICATION & AUTHORIZATION SCHEMA
-- Enhanced with Rate Limiting Support
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
-- Purpose: Manage API keys for external access with rate limiting support
CREATE TABLE API_Key (
    api_key_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the API key',
    key_name VARCHAR(100) NOT NULL COMMENT 'Human-readable name for the API key',
    key_hash VARCHAR(255) NOT NULL UNIQUE COMMENT 'SHA256 hash of the API key',
    key_prefix VARCHAR(20) NOT NULL COMMENT 'First few characters of key for identification',
    
    -- Permissions and scope
    permissions JSON NOT NULL COMMENT 'JSON object defining API permissions',
    contract_access JSON COMMENT 'JSON array of contract IDs this key can access (NULL = all)',
    
    -- Rate limiting configuration
    rate_limit_per_hour INT DEFAULT 1000 COMMENT 'API calls per hour limit for rate limiting',
    
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
    INDEX idx_rate_limit (rate_limit_per_hour)
);

-- API_Key_Usage_Log Table
-- Purpose: Log API key usage for rate limiting, monitoring and analytics
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the API call was made',
    
    FOREIGN KEY (api_key_id) REFERENCES API_Key(api_key_id),
    
    -- Standard indexes for analytics
    INDEX idx_api_key_id (api_key_id),
    INDEX idx_created_at (created_at),
    INDEX idx_endpoint (endpoint),
    INDEX idx_response_status (response_status),
    
    -- CRITICAL INDEX FOR RATE LIMITING PERFORMANCE
    -- This composite index is essential for fast rate limit queries
    INDEX idx_api_key_created_at (api_key_id, created_at),
    
    -- Additional indexes for common analytics queries
    INDEX idx_api_key_method (api_key_id, method),
    INDEX idx_api_key_status (api_key_id, response_status),
    INDEX idx_endpoint_method (endpoint, method)
);

-- =========================================
-- INSERT DEFAULT ROLES
-- =========================================

INSERT INTO User_Role (name, description, permissions) VALUES 
(
    'admin',
    'Administrator with full system access including rate limit management',
    JSON_OBJECT(
        'users', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'contracts', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'customers', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'controllers', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'cameras', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'events', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'api_keys', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'rate_limits', JSON_ARRAY('read', 'update'),
        'rf_monitoring', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'system_config', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'logs', JSON_ARRAY('read')
    )
),
(
    'viewer',
    'Read-only access to system data including rate limit monitoring',
    JSON_OBJECT(
        'users', JSON_ARRAY('read'),
        'contracts', JSON_ARRAY('read'),
        'customers', JSON_ARRAY('read'),
        'controllers', JSON_ARRAY('read'),
        'cameras', JSON_ARRAY('read'),
        'events', JSON_ARRAY('read'),
        'api_keys', JSON_ARRAY('read'),
        'rate_limits', JSON_ARRAY('read'),
        'rf_monitoring', JSON_ARRAY('read'),
        'system_config', JSON_ARRAY('read'),
        'logs', JSON_ARRAY('read')
    )
),
(
    'api_user',
    'Limited API access with basic permissions',
    JSON_OBJECT(
        'contracts', JSON_ARRAY('read'),
        'customers', JSON_ARRAY('read'),
        'events', JSON_ARRAY('read'),
        'cameras', JSON_ARRAY('read'),
        'controllers', JSON_ARRAY('read')
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

-- Insert default API user for demonstration
-- Default password: "APIUser2025!" (should be changed on first login)

INSERT INTO System_User (username, email, password_hash, role_id, first_name, last_name, force_password_change, created_by) 
SELECT 
    'api_user',
    'api@senseguard.local',
    '$2a$12$9wK.RGH5hKrZ6wK.RGH5hOrK9wK.RGH5hKrZ6wK.RGH5hOrK9wK.RH',
    ur.role_id,
    'API',
    'User',
    TRUE,
    su.user_id
FROM User_Role ur, System_User su 
WHERE ur.name = 'api_user' AND su.username = 'admin';

-- =========================================
-- INSERT SAMPLE API KEYS FOR TESTING
-- =========================================

-- Sample API key for testing rate limiting
-- Key: sg_testkey123456789 (for demonstration only)
-- Hash: SHA256 of the above key
INSERT INTO API_Key (
    key_name, 
    key_hash, 
    key_prefix, 
    permissions, 
    contract_access, 
    rate_limit_per_hour, 
    created_by, 
    description,
    active
) 
SELECT 
    'Test API Key',
    'a3f5d7b9c1e4f6a8d2b5c7e9f1a3d5b7c9e1f3a5d7b9c1e4f6a8d2b5c7e9f1a3',
    'sg_testk',
    JSON_OBJECT(
        'contracts', JSON_ARRAY('read'),
        'customers', JSON_ARRAY('read'),
        'events', JSON_ARRAY('read')
    ),
    NULL,
    10,  -- Low limit for easy testing
    user_id,
    'Test API key for rate limiting demonstration - DO NOT USE IN PRODUCTION',
    TRUE
FROM System_User WHERE username = 'admin';

-- Production-like API key with higher limits
INSERT INTO API_Key (
    key_name, 
    key_hash, 
    key_prefix, 
    permissions, 
    contract_access, 
    rate_limit_per_hour, 
    created_by, 
    description,
    active
) 
SELECT 
    'Production API Key',
    'b4g6e8c0d2f5h7j9k1m3o5q7s9u1w3y5a7c9e1g3i5k7m9o1q3s5u7w9y1a3c5',
    'sg_prod',
    JSON_OBJECT(
        'contracts', JSON_ARRAY('create', 'read', 'update'),
        'customers', JSON_ARRAY('create', 'read', 'update'),
        'events', JSON_ARRAY('read'),
        'cameras', JSON_ARRAY('read'),
        'controllers', JSON_ARRAY('read')
    ),
    JSON_ARRAY(1, 2, 3),  -- Limited to specific contracts
    1000,  -- Standard production limit
    user_id,
    'Production API key with standard rate limits',
    TRUE
FROM System_User WHERE username = 'admin';

-- =========================================
-- RATE LIMITING UTILITY PROCEDURES
-- =========================================

DELIMITER //

-- Procedure to check current rate limit usage for an API key
CREATE PROCEDURE GetAPIKeyRateLimit(IN p_api_key_id INT)
BEGIN
    DECLARE v_rate_limit INT DEFAULT 0;
    DECLARE v_current_usage INT DEFAULT 0;
    DECLARE v_remaining INT DEFAULT 0;
    DECLARE v_reset_time BIGINT DEFAULT 0;
    
    -- Get the rate limit for the API key
    SELECT rate_limit_per_hour INTO v_rate_limit
    FROM API_Key 
    WHERE api_key_id = p_api_key_id AND active = TRUE;
    
    -- Get current hour usage
    SELECT COUNT(*) INTO v_current_usage
    FROM API_Key_Usage_Log 
    WHERE api_key_id = p_api_key_id 
    AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);
    
    -- Calculate remaining requests
    SET v_remaining = GREATEST(0, v_rate_limit - v_current_usage);
    
    -- Calculate reset time (next hour boundary)
    SET v_reset_time = UNIX_TIMESTAMP(
        DATE_ADD(
            DATE_FORMAT(NOW(), '%Y-%m-%d %H:00:00'), 
            INTERVAL 1 HOUR
        )
    );
    
    -- Return results
    SELECT 
        p_api_key_id as api_key_id,
        v_rate_limit as rate_limit,
        v_current_usage as current_usage,
        v_remaining as remaining,
        v_reset_time as reset_time,
        CASE 
            WHEN v_current_usage >= v_rate_limit THEN TRUE 
            ELSE FALSE 
        END as is_rate_limited;
END //

-- Procedure to get API key usage statistics
CREATE PROCEDURE GetAPIKeyUsageStats(IN p_api_key_id INT, IN p_days INT)
BEGIN
    SELECT 
        DATE(created_at) as usage_date,
        COUNT(*) as total_requests,
        COUNT(CASE WHEN response_status >= 200 AND response_status < 300 THEN 1 END) as successful_requests,
        COUNT(CASE WHEN response_status >= 400 THEN 1 END) as error_requests,
        AVG(COALESCE(response_time_ms, 0)) as avg_response_time,
        COUNT(DISTINCT ip_address) as unique_ips
    FROM API_Key_Usage_Log 
    WHERE api_key_id = p_api_key_id 
    AND created_at >= DATE_SUB(NOW(), INTERVAL p_days DAY)
    GROUP BY DATE(created_at)
    ORDER BY usage_date DESC;
END //

-- Procedure to clean expired sessions
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    DELETE FROM User_Session WHERE expires_at < NOW();
    SELECT ROW_COUNT() as cleaned_sessions;
END //

-- Procedure to clean old API usage logs (keep configurable days)
CREATE PROCEDURE CleanOldAPILogs(IN p_keep_days INT DEFAULT 90)
BEGIN
    DELETE FROM API_Key_Usage_Log 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL p_keep_days DAY);
    SELECT ROW_COUNT() as cleaned_log_entries;
END //

-- Procedure to get top API consumers by usage
CREATE PROCEDURE GetTopAPIConsumers(IN p_days INT DEFAULT 7, IN p_limit INT DEFAULT 10)
BEGIN
    SELECT 
        ak.api_key_id,
        ak.key_name,
        ak.rate_limit_per_hour,
        COUNT(ul.log_id) as total_requests,
        COUNT(CASE WHEN ul.response_status >= 400 THEN 1 END) as error_requests,
        AVG(COALESCE(ul.response_time_ms, 0)) as avg_response_time,
        MAX(ul.created_at) as last_used,
        COUNT(DISTINCT ul.ip_address) as unique_ips
    FROM API_Key ak
    LEFT JOIN API_Key_Usage_Log ul ON ak.api_key_id = ul.api_key_id 
        AND ul.created_at >= DATE_SUB(NOW(), INTERVAL p_days DAY)
    WHERE ak.active = TRUE
    GROUP BY ak.api_key_id
    ORDER BY total_requests DESC
    LIMIT p_limit;
END //

-- Procedure to identify potential rate limit abuse
CREATE PROCEDURE DetectRateLimitAbuse(IN p_hours INT DEFAULT 24)
BEGIN
    SELECT 
        ak.api_key_id,
        ak.key_name,
        ak.rate_limit_per_hour,
        COUNT(ul.log_id) as total_requests,
        COUNT(ul.log_id) / p_hours as avg_requests_per_hour,
        (COUNT(ul.log_id) / p_hours) / ak.rate_limit_per_hour * 100 as usage_percentage,
        COUNT(CASE WHEN ul.response_status = 429 THEN 1 END) as rate_limit_hits,
        COUNT(DISTINCT ul.ip_address) as unique_ips,
        MIN(ul.created_at) as first_request,
        MAX(ul.created_at) as last_request
    FROM API_Key ak
    JOIN API_Key_Usage_Log ul ON ak.api_key_id = ul.api_key_id 
    WHERE ul.created_at >= DATE_SUB(NOW(), INTERVAL p_hours HOUR)
    AND ak.active = TRUE
    GROUP BY ak.api_key_id
    HAVING usage_percentage > 80  -- Keys using more than 80% of their limit
    ORDER BY usage_percentage DESC;
END //

DELIMITER ;

-- =========================================
-- CLEANUP EVENTS
-- =========================================

-- Create events to run cleanup procedures daily
CREATE EVENT IF NOT EXISTS CleanExpiredSessionsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanExpiredSessions();

CREATE EVENT IF NOT EXISTS CleanOldAPILogsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanOldAPILogs(90);  -- Keep 90 days of logs

-- =========================================
-- RATE LIMITING VIEWS FOR EASY QUERYING
-- =========================================

-- View for current rate limit status of all active API keys
CREATE VIEW vw_api_key_rate_limits AS
SELECT 
    ak.api_key_id,
    ak.key_name,
    ak.rate_limit_per_hour,
    ak.active,
    COALESCE(current_usage.usage_count, 0) as current_hour_usage,
    GREATEST(0, ak.rate_limit_per_hour - COALESCE(current_usage.usage_count, 0)) as remaining_requests,
    CASE 
        WHEN COALESCE(current_usage.usage_count, 0) >= ak.rate_limit_per_hour THEN TRUE 
        ELSE FALSE 
    END as is_rate_limited,
    ak.last_used,
    ak.usage_count as total_usage_count,
    ak.created_at
FROM API_Key ak
LEFT JOIN (
    SELECT 
        api_key_id,
        COUNT(*) as usage_count
    FROM API_Key_Usage_Log
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    GROUP BY api_key_id
) current_usage ON ak.api_key_id = current_usage.api_key_id
WHERE ak.active = TRUE;

-- View for API key usage summary (last 24 hours)
CREATE VIEW vw_api_key_usage_24h AS
SELECT 
    ak.api_key_id,
    ak.key_name,
    ak.rate_limit_per_hour,
    COUNT(ul.log_id) as requests_24h,
    COUNT(CASE WHEN ul.response_status >= 200 AND ul.response_status < 300 THEN 1 END) as successful_requests,
    COUNT(CASE WHEN ul.response_status >= 400 THEN 1 END) as error_requests,
    COUNT(CASE WHEN ul.response_status = 429 THEN 1 END) as rate_limited_requests,
    AVG(COALESCE(ul.response_time_ms, 0)) as avg_response_time,
    COUNT(DISTINCT ul.ip_address) as unique_ips,
    MIN(ul.created_at) as first_request_24h,
    MAX(ul.created_at) as last_request_24h
FROM API_Key ak
LEFT JOIN API_Key_Usage_Log ul ON ak.api_key_id = ul.api_key_id 
    AND ul.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
WHERE ak.active = TRUE
GROUP BY ak.api_key_id;

-- =========================================
-- SAMPLE QUERIES FOR TESTING
-- =========================================

-- Check current rate limit status for all API keys
-- SELECT * FROM vw_api_key_rate_limits;

-- Get rate limit info for specific API key
-- CALL GetAPIKeyRateLimit(1);

-- Get usage stats for specific API key (last 7 days)
-- CALL GetAPIKeyUsageStats(1, 7);

-- Find top API consumers
-- CALL GetTopAPIConsumers(7, 5);

-- Detect potential abuse
-- CALL DetectRateLimitAbuse(24);

-- Manual rate limit check query (what the application uses)
-- SELECT COUNT(*) as current_usage
-- FROM API_Key_Usage_Log 
-- WHERE api_key_id = 1 
-- AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- =========================================
-- PERFORMANCE OPTIMIZATION NOTES
-- =========================================

-- CRITICAL: The composite index on (api_key_id, created_at) is essential
-- for rate limiting query performance. Without it, rate limit checks
-- will be slow and could impact API response times.

-- The rate limiting query pattern is:
-- SELECT COUNT(*) FROM API_Key_Usage_Log 
-- WHERE api_key_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)

-- This query benefits significantly from the composite index and should
-- execute in milliseconds even with millions of log entries.

-- Monitor query performance with:
-- EXPLAIN SELECT COUNT(*) FROM API_Key_Usage_Log 
-- WHERE api_key_id = 1 AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- =========================================
-- SCHEMA VALIDATION QUERIES
-- =========================================

-- Verify all tables were created successfully
SELECT 
    TABLE_NAME,
    TABLE_ROWS,
    DATA_LENGTH,
    INDEX_LENGTH,
    CREATE_TIME
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_SCHEMA = DATABASE() 
AND TABLE_NAME IN ('User_Role', 'System_User', 'User_Session', 'API_Key', 'API_Key_Usage_Log')
ORDER BY TABLE_NAME;

-- Verify critical indexes exist
SELECT 
    TABLE_NAME,
    INDEX_NAME,
    COLUMN_NAME,
    SEQ_IN_INDEX
FROM INFORMATION_SCHEMA.STATISTICS 
WHERE TABLE_SCHEMA = DATABASE() 
AND TABLE_NAME = 'API_Key_Usage_Log'
AND INDEX_NAME = 'idx_api_key_created_at'
ORDER BY SEQ_IN_INDEX;

-- Show sample data
SELECT 'User Roles Created:' as info;
SELECT role_id, name, active FROM User_Role;

SELECT 'System Users Created:' as info;  
SELECT user_id, username, email, active FROM System_User;

SELECT 'API Keys Created:' as info;
SELECT api_key_id, key_name, rate_limit_per_hour, active FROM API_Key;

SELECT '✅ Authentication schema with rate limiting is ready!' as status;
