-- =========================================
-- AUTHENTICATION & AUTHORIZATION SCHEMA
-- Purpose: Complete authentication system for admin users and API key management
-- Features: Role-based permissions, JWT sessions, API key rate limiting, audit logging
-- Security: Bcrypt password hashing, session management, comprehensive audit trails
-- Version: 2.0 with enhanced rate limiting and customer authentication support
-- Updated: 2025-01-14
-- =========================================

-- =========================================
-- ROLE AND PERMISSION MANAGEMENT
-- Purpose: Define system roles and granular permissions for admin users
-- Usage: Controls access to different parts of the admin interface and API
-- Architecture: JSON-based permissions for flexibility and easy extension
-- =========================================

-- User_Role Table
-- Purpose: Define administrative roles with specific permission sets
-- Usage: Admin roles (admin, viewer) with granular permission control
-- Permissions: JSON structure allows flexible permission assignment per resource
-- Future: Easily extensible for new resources and permission types
CREATE TABLE User_Role (
    role_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the administrative role',
    name VARCHAR(50) NOT NULL UNIQUE COMMENT 'Role name (e.g., "admin", "viewer", "operator")',
    description TEXT COMMENT 'Human-readable description of role responsibilities and permissions',
    permissions JSON NOT NULL COMMENT 'JSON object defining granular permissions: {"users": ["create", "read", "update", "delete"], "contracts": ["read", "update"], ...}',
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether this role is active and can be assigned to users',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When this role was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'When this role was last modified'
);

-- System_User Table
-- Purpose: Administrative user accounts for system management
-- Usage: Admin interface login, API access, system management
-- Security: Bcrypt password hashing, account locking, session tracking
-- Audit: Failed login tracking, last login timestamps, password aging
CREATE TABLE System_User (
    user_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the administrative user',
    username VARCHAR(50) NOT NULL UNIQUE COMMENT 'Unique username for admin login (not email-based)',
    email VARCHAR(255) NOT NULL UNIQUE COMMENT 'User email address for notifications and password recovery',
    password_hash VARCHAR(255) NOT NULL COMMENT 'Bcrypt hashed password (never store plaintext passwords)',
    role_id INT NOT NULL COMMENT 'Reference to assigned administrative role',
    first_name VARCHAR(100) COMMENT 'User first name for display and audit trails',
    last_name VARCHAR(100) COMMENT 'User last name for display and audit trails',

    -- SECURITY AND AUTHENTICATION FIELDS
    -- Purpose: Account security, password policies, and session management
    force_password_change BOOLEAN DEFAULT TRUE COMMENT 'Force password change on next login (new accounts, admin resets)',
    last_login TIMESTAMP NULL COMMENT 'Timestamp of last successful login for security monitoring',
    failed_login_attempts INT DEFAULT 0 COMMENT 'Consecutive failed login attempts (resets on success)',
    locked_until TIMESTAMP NULL COMMENT 'Account locked until this timestamp (auto-lock after 5 failed attempts)',
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When password was last changed (for password aging policies)',

    -- ACCOUNT MANAGEMENT
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether user account is active (deactivated users cannot login)',
    created_by INT COMMENT 'User ID of administrator who created this account (audit trail)',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When this user account was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'When this user account was last modified',

    -- FOREIGN KEY RELATIONSHIPS
    FOREIGN KEY (role_id) REFERENCES User_Role(role_id) ON DELETE RESTRICT COMMENT 'Prevent deletion of roles assigned to users',
    FOREIGN KEY (created_by) REFERENCES System_User(user_id) ON DELETE SET NULL COMMENT 'Track account creator for audit',

    -- PERFORMANCE INDEXES FOR AUTHENTICATION
    INDEX idx_username (username) COMMENT 'Fast username lookup for login authentication',
    INDEX idx_email (email) COMMENT 'Email-based lookup for password recovery',
    INDEX idx_role (role_id) COMMENT 'Role-based user queries and permission checks',
    INDEX idx_active (active) COMMENT 'Filter active/inactive users in admin interface'
);

-- =========================================
-- SESSION MANAGEMENT FOR ADMIN USERS
-- Purpose: Track active admin user sessions and JWT tokens
-- Security: Token hash verification, IP tracking, session expiration
-- Analytics: Session duration, user activity patterns, security monitoring
-- =========================================

-- User_Session Table
-- Purpose: Manage active administrative user sessions
-- Usage: JWT token validation, session security, concurrent session tracking
-- Security: Stores token hashes (not actual tokens), IP and browser tracking
-- Cleanup: Automatic cleanup of expired sessions via scheduled events
CREATE TABLE User_Session (
    session_id VARCHAR(255) PRIMARY KEY COMMENT 'Unique session identifier (matches JWT jti claim)',
    user_id INT NOT NULL COMMENT 'Reference to the administrative user who owns this session',
    token_hash VARCHAR(255) NOT NULL COMMENT 'SHA256 hash of JWT token (for validation without storing actual token)',
    ip_address VARCHAR(45) COMMENT 'IP address of the admin session (IPv4/IPv6 support)',
    user_agent TEXT COMMENT 'Browser user agent string (for device tracking and security)',
    expires_at TIMESTAMP NOT NULL COMMENT 'When the session expires (typically 24 hours)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the session was created',
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last API activity (updated on each request)',

    FOREIGN KEY (user_id) REFERENCES System_User(user_id) ON DELETE CASCADE COMMENT 'Delete sessions when user is deleted',

    -- SESSION MANAGEMENT INDEXES
    INDEX idx_user_id (user_id) COMMENT 'Fast lookup of sessions by user for management',
    INDEX idx_expires_at (expires_at) COMMENT 'Efficient cleanup of expired sessions',
    INDEX idx_token_hash (token_hash) COMMENT 'Fast token validation during authentication'
);

-- =========================================
-- API KEY MANAGEMENT SYSTEM
-- Purpose: External API access with rate limiting and permission control
-- Usage: Third-party integrations, automated systems, mobile apps
-- Security: Scoped permissions, rate limiting, usage tracking, expiration
-- =========================================

-- API_Key Table
-- Purpose: Manage API keys for external system access
-- Usage: Third-party integrations, mobile apps, automated monitoring systems
-- Security: Hashed keys, scoped permissions, contract-level access control, rate limiting
-- Management: Expiration dates, usage tracking, comprehensive audit logging
CREATE TABLE API_Key (
    api_key_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the API key',
    key_name VARCHAR(100) NOT NULL COMMENT 'Human-readable name for identification (e.g., "Mobile App", "Monitoring System")',
    key_hash VARCHAR(255) NOT NULL UNIQUE COMMENT 'SHA256 hash of the actual API key (key never stored in plaintext)',
    key_prefix VARCHAR(20) NOT NULL COMMENT 'First few characters of key for identification in logs and UI',

    -- PERMISSIONS AND ACCESS CONTROL
    -- Purpose: Fine-grained control over API key capabilities and data access
    permissions JSON NOT NULL COMMENT 'JSON object defining API permissions: {"contracts": ["read"], "customers": ["read"], ...}',
    contract_access JSON COMMENT 'JSON array of contract IDs this key can access (NULL = all contracts)',
    rate_limit_per_hour INT DEFAULT 1000 COMMENT 'Maximum API calls per hour (prevents abuse and controls costs)',

    -- KEY METADATA AND MANAGEMENT
    created_by INT NOT NULL COMMENT 'Administrative user who created this API key',
    description TEXT COMMENT 'Purpose and usage description of this API key',

    -- SECURITY AND STATUS TRACKING
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether the API key is active and can be used',
    last_used TIMESTAMP NULL COMMENT 'Last time this API key was used for an API call',
    usage_count BIGINT DEFAULT 0 COMMENT 'Total number of API calls made with this key',

    -- EXPIRATION AND LIFECYCLE MANAGEMENT
    expires_at TIMESTAMP NULL COMMENT 'When the API key expires (NULL = no expiration)',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When this API key was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'When this API key was last modified',

    FOREIGN KEY (created_by) REFERENCES System_User(user_id) ON DELETE RESTRICT COMMENT 'Prevent deletion of users who created API keys',

    -- API KEY MANAGEMENT INDEXES
    INDEX idx_key_hash (key_hash) COMMENT 'Fast API key lookup during authentication',
    INDEX idx_key_prefix (key_prefix) COMMENT 'Key identification in logs and admin interface',
    INDEX idx_created_by (created_by) COMMENT 'Track API keys by creator for management',
    INDEX idx_active (active) COMMENT 'Filter active/inactive API keys',
    INDEX idx_expires_at (expires_at) COMMENT 'Monitor and cleanup expired API keys',
    INDEX idx_active_rate_limit (active, rate_limit_per_hour) COMMENT 'Rate limiting queries for active keys'
);

-- =========================================
-- API USAGE LOGGING AND ANALYTICS
-- Purpose: Comprehensive logging of API key usage for security and analytics
-- Usage: Rate limiting enforcement, usage analytics, security monitoring, billing
-- Retention: Configurable retention period (default 90 days) for performance
-- =========================================

-- API_Key_Usage_Log Table
-- Purpose: Detailed logging of every API key usage for analytics and security
-- Usage: Rate limiting calculations, usage analytics, security incident investigation
-- Performance: High-volume table with automated cleanup and optimized indexes
-- Analytics: Response times, error rates, usage patterns, abuse detection
CREATE TABLE API_Key_Usage_Log (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the usage log entry (BIGINT for high volume)',
    api_key_id INT NOT NULL COMMENT 'Reference to the API key that was used',
    endpoint VARCHAR(255) NOT NULL COMMENT 'API endpoint that was called (e.g., "/contracts", "/customers/123")',
    method ENUM('GET', 'POST', 'PUT', 'DELETE', 'PATCH') NOT NULL COMMENT 'HTTP method used for the API call',
    ip_address VARCHAR(45) COMMENT 'IP address of the API client (IPv4/IPv6 support)',
    user_agent TEXT COMMENT 'Client user agent string (for client identification)',
    response_status INT COMMENT 'HTTP response status code (200, 401, 403, 429, 500, etc.)',
    response_time_ms INT COMMENT 'API response time in milliseconds (for performance monitoring)',
    request_size_bytes INT COMMENT 'Size of the request payload in bytes',
    response_size_bytes INT COMMENT 'Size of the response payload in bytes',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the API call was made',

    FOREIGN KEY (api_key_id) REFERENCES API_Key(api_key_id) ON DELETE CASCADE COMMENT 'Delete logs when API key is deleted',

    -- HIGH-PERFORMANCE INDEXES FOR ANALYTICS AND RATE LIMITING
    INDEX idx_api_key_id (api_key_id) COMMENT 'Fast lookup by API key for usage statistics',
    INDEX idx_created_at (created_at) COMMENT 'Time-based queries and cleanup operations',
    INDEX idx_endpoint (endpoint) COMMENT 'Endpoint-specific usage analytics',
    INDEX idx_response_status (response_status) COMMENT 'Error rate and success rate analysis',
    INDEX idx_api_usage_key_time (api_key_id, created_at) COMMENT 'Composite index for rate limiting queries',
    INDEX idx_api_usage_time_status (created_at, response_status) COMMENT 'Time-based error analysis'
);

-- =========================================
-- SYSTEM LOGGING AND AUDIT TRAIL
-- Purpose: Comprehensive system event logging for security and compliance
-- Usage: Security events, configuration changes, error tracking, compliance audits
-- =========================================

-- System_Log Table
-- Purpose: Central logging for system events, errors, and administrative actions
-- Usage: Security monitoring, debugging, compliance auditing, system health tracking
-- Categories: Authentication events, configuration changes, errors, security incidents
CREATE TABLE System_Log (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the log entry',
    log_level ENUM('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL') NOT NULL COMMENT 'Log severity level for filtering and alerting',
    component VARCHAR(50) NOT NULL COMMENT 'System component that generated the log (e.g., "AUTH", "API", "ADMIN")',
    message TEXT NOT NULL COMMENT 'Human-readable log message describing the event',
    metadata JSON COMMENT 'Additional structured data related to the event (user_id, ip_address, etc.)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the log event occurred',

    -- LOGGING AND MONITORING INDEXES
    INDEX idx_log_level (log_level) COMMENT 'Filter logs by severity for monitoring and alerting',
    INDEX idx_component (component) COMMENT 'Component-specific log analysis',
    INDEX idx_created_at (created_at) COMMENT 'Time-based log queries and cleanup'
);

-- =========================================
-- RATE LIMITING VIEWS AND ANALYTICS
-- Purpose: Real-time rate limiting data and comprehensive usage analytics
-- Usage: Rate limiting enforcement, API key management, usage monitoring
-- Performance: Optimized views for real-time rate limiting decisions
-- =========================================

-- API_Key_Usage_Last_Hour View
-- Purpose: Real-time rate limiting data for API key usage enforcement
-- Usage: Called on every API request to check rate limits before processing
-- Performance: Optimized for fast rate limiting decisions (<1ms query time)
-- Critical: This view is essential for preventing API abuse and maintaining system stability
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

-- API_Key_Usage_Stats View
-- Purpose: Comprehensive API key usage analytics and performance metrics
-- Usage: Admin dashboard, API key management, usage reporting, billing analytics
-- Metrics: Usage patterns, error rates, performance statistics, rate limiting status
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

    -- USAGE STATISTICS ACROSS DIFFERENT TIME PERIODS
    -- Purpose: Trend analysis and capacity planning
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as usage_last_hour,
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as usage_last_24h,
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as usage_last_7d,
    COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as usage_last_30d,

    -- SUCCESS AND ERROR RATE ANALYSIS
    -- Purpose: API health monitoring and client issue detection
    COUNT(CASE WHEN ul.response_status >= 200 AND ul.response_status < 300 THEN 1 END) as successful_requests,
    COUNT(CASE WHEN ul.response_status >= 400 THEN 1 END) as error_requests,
    COUNT(CASE WHEN ul.response_status = 429 THEN 1 END) as rate_limited_requests,

    -- PERFORMANCE METRICS
    -- Purpose: API performance monitoring and optimization insights
    AVG(ul.response_time_ms) as avg_response_time_ms,
    MAX(ul.response_time_ms) as max_response_time_ms,
    MIN(ul.response_time_ms) as min_response_time_ms,

    -- REAL-TIME RATE LIMITING STATUS
    -- Purpose: Current rate limiting state for admin monitoring
    ak.rate_limit_per_hour - COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as remaining_requests_this_hour,
    CASE
        WHEN COUNT(CASE WHEN ul.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) >= ak.rate_limit_per_hour THEN TRUE
        ELSE FALSE
    END as currently_rate_limited,

    -- ACTIVITY AND ENGAGEMENT METRICS
    MAX(ul.created_at) as last_request_time,
    COUNT(DISTINCT DATE(ul.created_at)) as active_days,

    -- AUDIT AND MANAGEMENT INFORMATION
    creator.username as created_by_username

FROM API_Key ak
LEFT JOIN API_Key_Usage_Log ul ON ak.api_key_id = ul.api_key_id
LEFT JOIN System_User creator ON ak.created_by = creator.user_id
GROUP BY ak.api_key_id, ak.key_name, ak.key_prefix, ak.rate_limit_per_hour,
         ak.active, ak.created_at, ak.last_used, ak.usage_count, creator.username;

-- =========================================
-- STORED PROCEDURES FOR AUTOMATION AND MAINTENANCE
-- Purpose: Automated system maintenance, rate limiting, and data cleanup
-- Usage: Scheduled execution for database hygiene and performance optimization
-- =========================================

DELIMITER //

-- CheckAPIKeyRateLimit Procedure
-- Purpose: Real-time rate limiting check for API key requests
-- Usage: Called by application before processing API requests
-- Performance: Optimized for sub-millisecond response times
-- Critical: Essential for API abuse prevention and system stability
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

    -- Get the API key's rate limit configuration
    SELECT rate_limit_per_hour
    INTO v_rate_limit_per_hour
    FROM API_Key
    WHERE api_key_id = p_api_key_id AND active = TRUE;

    -- Count usage in the last hour for rate limiting decision
    SELECT COUNT(*)
    INTO v_usage_last_hour
    FROM API_Key_Usage_Log
    WHERE api_key_id = p_api_key_id
    AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);

    -- Set output parameters for application decision making
    SET p_usage_count = v_usage_last_hour;
    SET p_rate_limit = v_rate_limit_per_hour;
    SET p_remaining = v_rate_limit_per_hour - v_usage_last_hour;
    SET p_can_proceed = (v_usage_last_hour < v_rate_limit_per_hour);
END //

-- GetAllAPIKeyRateLimitStatus Procedure
-- Purpose: Comprehensive rate limiting status for admin dashboard
-- Usage: Admin interface monitoring of all API key usage and limits
-- Analytics: Identifies approaching limits and usage patterns
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

-- CleanExpiredSessions Procedure
-- Purpose: Remove expired admin user sessions for database hygiene
-- Usage: Daily cleanup to prevent session table growth and maintain performance
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    
    DELETE FROM User_Session WHERE expires_at < NOW();
    SET deleted_count = ROW_COUNT();
    
    -- Log cleanup activity for monitoring
    INSERT INTO System_Log (log_level, component, message, metadata, created_at)
    VALUES ('INFO', 'SESSION_CLEANUP', 'Cleaned expired admin sessions', 
            JSON_OBJECT('deleted_sessions', deleted_count), NOW());
END //

-- CleanOldAPILogs Procedure
-- Purpose: Remove old API usage logs to maintain database performance
-- Usage: Daily cleanup with configurable retention period (default 90 days)
-- Performance: Prevents API_Key_Usage_Log table from growing unbounded
CREATE PROCEDURE CleanOldAPILogs()
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    
    DELETE FROM API_Key_Usage_Log WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
    SET deleted_count = ROW_COUNT();
    
    -- Log cleanup activity for monitoring
    INSERT INTO System_Log (log_level, component, message, metadata, created_at)
    VALUES ('INFO', 'API_LOG_CLEANUP', 'Cleaned old API usage logs', 
            JSON_OBJECT('deleted_logs', deleted_count, 'retention_days', 90), NOW());
END //

-- CleanupRateLimitingData Procedure
-- Purpose: Comprehensive cleanup of rate limiting and usage data
-- Usage: Daily maintenance for optimal rate limiting performance
CREATE PROCEDURE CleanupRateLimitingData()
BEGIN
    DECLARE v_deleted_logs INT DEFAULT 0;
    DECLARE v_deleted_sessions INT DEFAULT 0;

    -- Delete API usage logs older than retention period
    DELETE FROM API_Key_Usage_Log
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
    SET v_deleted_logs = ROW_COUNT();

    -- Delete expired user sessions
    DELETE FROM User_Session WHERE expires_at < NOW();
    SET v_deleted_sessions = ROW_COUNT();

    -- Log comprehensive cleanup results
    INSERT INTO System_Log (log_level, component, message, metadata, created_at)
    VALUES (
        'INFO',
        'RATE_LIMITING',
        'Comprehensive rate limiting data cleanup completed',
        JSON_OBJECT(
            'deleted_api_logs', v_deleted_logs,
            'deleted_sessions', v_deleted_sessions,
            'retention_days', 90
        ),
        NOW()
    );
END //

DELIMITER ;

-- =========================================
-- DEFAULT SYSTEM ROLES AND USERS
-- Purpose: Bootstrap the system with essential administrative roles and default users
-- Security: Default passwords must be changed on first login
-- =========================================

-- Insert Default Administrative Roles
-- Purpose: Create fundamental admin and viewer roles with appropriate permissions
-- Permissions: Admin has full access, viewer has read-only access to most resources
INSERT INTO User_Role (name, description, permissions) VALUES
(
    'admin',
    'System Administrator with full access to all resources and functions',
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
        'service_tiers', JSON_ARRAY('create', 'read', 'update', 'delete'),
        'diagnostics', JSON_ARRAY('read')
    )
),
(
    'viewer',
    'Read-only access to system data for monitoring and reporting purposes',
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
        'service_tiers', JSON_ARRAY('read'),
        'diagnostics', JSON_ARRAY('read')
    )
);

-- Insert Default System Administrator
-- Purpose: Create initial admin user for system bootstrap
-- Security: Default password must be changed on first login (force_password_change = TRUE)
-- Credentials: Username: admin, Password: SenseGuard2025! (change immediately)
INSERT INTO System_User (username, email, password_hash, role_id, first_name, last_name, force_password_change)
SELECT
    'admin',
    'admin@senseguard.local',
    '$2a$12$8vJ.QGH5gKqY5vJ.QGH5gOqJ8vJ.QGH5gKqY5vJ.QGH5gOqJ8vJ.QG', -- BCrypt hash of "SenseGuard2025!"
    role_id,
    'System',
    'Administrator',
    TRUE
FROM User_Role WHERE name = 'admin';

-- Insert Default Viewer User
-- Purpose: Create initial viewer user for read-only access
-- Security: Default password must be changed on first login
-- Credentials: Username: viewer, Password: Viewer2025! (change immediately)
INSERT INTO System_User (username, email, password_hash, role_id, first_name, last_name, force_password_change, created_by)
SELECT
    'viewer',
    'viewer@senseguard.local',
    '$2a$12$7uI.PGH5fJpX4uI.PGH5fNpI7uI.PGH5fJpX4uI.PGH5fNpI7uI.PF', -- BCrypt hash of "Viewer2025!"
    ur.role_id,
    'System',
    'Viewer',
    TRUE,
    su.user_id
FROM User_Role ur, System_User su
WHERE ur.name = 'viewer' AND su.username = 'admin';

-- =========================================
-- AUTOMATED MAINTENANCE SCHEDULED EVENTS
-- Purpose: Automatic execution of maintenance procedures for system health
-- Frequency: Daily execution during low-usage periods (typically 2-4 AM)
-- =========================================

-- Admin Session Cleanup Event
-- Purpose: Daily cleanup of expired administrative sessions
CREATE EVENT IF NOT EXISTS CleanExpiredSessionsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanExpiredSessions()
COMMENT 'Daily cleanup of expired administrative user sessions';

-- API Usage Log Cleanup Event  
-- Purpose: Daily cleanup of old API usage logs (90-day retention)
CREATE EVENT IF NOT EXISTS CleanOldAPILogsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanOldAPILogs()
COMMENT 'Daily cleanup of API usage logs older than 90 days';

-- Comprehensive Rate Limiting Cleanup Event
-- Purpose: Daily maintenance of all rate limiting and authentication data
CREATE EVENT IF NOT EXISTS RateLimitingCleanupEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanupRateLimitingData()
COMMENT 'Daily comprehensive cleanup of rate limiting and session data';-- =========================================
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
