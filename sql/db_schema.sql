-- =========================================
-- SENSE SECURITY PLATFORM - COMPLETE DATABASE SCHEMA
-- Includes Customer Authentication and Views
-- =========================================

-- Customer Table (UPDATED with authentication fields)
CREATE TABLE Customer (
    customer_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the customer',
    name_on_contract VARCHAR(255) NOT NULL COMMENT 'Name of the person on the contract',
    address TEXT NOT NULL COMMENT 'Physical address of the customer',
    unique_id VARCHAR(255) NOT NULL UNIQUE COMMENT 'Unique identifier for the customer (e.g., government ID or internal ID)',
    email VARCHAR(255) COMMENT 'Email address of the customer',
    phone_number VARCHAR(15) COMMENT 'Contact phone number of the customer',
    
    -- AUTHENTICATION FIELDS
    password_hash VARCHAR(255) COMMENT 'Bcrypt hashed password for customer login',
    force_password_change BOOLEAN DEFAULT TRUE COMMENT 'Force password change on next login',
    last_login TIMESTAMP NULL COMMENT 'Last successful login timestamp',
    failed_login_attempts INT DEFAULT 0 COMMENT 'Number of consecutive failed login attempts',
    locked_until TIMESTAMP NULL COMMENT 'Account locked until this timestamp',
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When password was last changed',
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether customer account is active',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the customer record was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the customer record was last updated',
    
    -- INDEXES
    INDEX idx_customer_email (email),
    INDEX idx_customer_active (active),
    INDEX idx_customer_locked (locked_until)
);

-- Customer Session Table
CREATE TABLE Customer_Session (
    session_id VARCHAR(255) PRIMARY KEY COMMENT 'Unique session identifier (JWT jti)',
    customer_id INT NOT NULL COMMENT 'Reference to the customer',
    token_hash VARCHAR(255) NOT NULL COMMENT 'SHA256 hash of the JWT token',
    ip_address VARCHAR(45) COMMENT 'IP address of the session',
    user_agent TEXT COMMENT 'User agent string',
    expires_at TIMESTAMP NOT NULL COMMENT 'When the session expires',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (customer_id) REFERENCES Customer(customer_id),

    INDEX idx_customer_id (customer_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_token_hash (token_hash)
);

-- Contract Table
CREATE TABLE Contract (
    contract_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the contract',
    service_address TEXT NOT NULL COMMENT 'Physical address where the service is provided',
    notification_email VARCHAR(255) COMMENT 'Email address for contract notifications',
    notification_phone VARCHAR(15) COMMENT 'Phone number for contract notifications',
    start_date DATE NOT NULL COMMENT 'Date when the contract becomes active',
    end_date DATE NOT NULL COMMENT 'Date when the contract expires',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the contract was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the contract was last updated',
    
    -- Performance indexes
    INDEX idx_start_end_date (start_date, end_date),
    
    -- Data integrity constraints
    CONSTRAINT chk_contract_dates CHECK (end_date > start_date)
);

-- Contract_Customer_Mapping Table
CREATE TABLE Contract_Customer_Mapping (
    contract_customer_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    contract_id INT NOT NULL COMMENT 'Reference to the contract',
    customer_id INT NOT NULL COMMENT 'Reference to the customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (contract_id) REFERENCES Contract(contract_id),
    FOREIGN KEY (customer_id) REFERENCES Customer(customer_id)
);

-- Service_Tier Table
CREATE TABLE Service_Tier (
    service_tier_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the service tier',
    name VARCHAR(50) NOT NULL COMMENT 'Name of the service tier (e.g., Gold, Silver)',
    description TEXT COMMENT 'Description of the service tier',
    config JSON COMMENT 'Service tier features (response_time_sla, video_retention_days, priority_level, etc.)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the service tier was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the service tier was last updated'
);

-- Contract_Service_Tier Table
CREATE TABLE Contract_Service_Tier (
    contract_service_tier_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the service tier assignment',
    contract_id INT NOT NULL COMMENT 'Reference to the contract',
    service_tier_id INT NOT NULL COMMENT 'Reference to the service tier',
    start_date DATE NOT NULL COMMENT 'Date when the service tier becomes active',
    end_date DATE NOT NULL COMMENT 'Date when the service tier expires',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the assignment was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the assignment was last updated',
    FOREIGN KEY (contract_id) REFERENCES Contract(contract_id),
    FOREIGN KEY (service_tier_id) REFERENCES Service_Tier(service_tier_id),
    
    -- Performance indexes
    INDEX idx_contract_dates (contract_id, start_date, end_date),
    
    -- Data integrity constraints
    CONSTRAINT chk_service_dates CHECK (end_date > start_date)
);

-- Unique constraint for non-overlapping service tiers per contract
CREATE UNIQUE INDEX idx_contract_active_tier 
    ON Contract_Service_Tier(contract_id, start_date, end_date);

-- NVR_Profile Table
CREATE TABLE NVR_Profile (
    profile_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the NVR profile',
    name VARCHAR(100) NOT NULL COMMENT 'Profile name (e.g., "Dahua-8Channel-4K")',
    manufacturer VARCHAR(50) NOT NULL COMMENT 'NVR manufacturer (e.g., Dahua, Hikvision)',
    api_type ENUM('ONVIF', 'ManufacturerAPI', 'RTSP') NOT NULL COMMENT 'Integration API type',
    auth_type ENUM('Basic', 'Digest', 'Token') NOT NULL COMMENT 'Authentication method',
    stream_config JSON NOT NULL COMMENT 'JSON configuration for video streams',
    event_config JSON COMMENT 'JSON configuration for event detection',
    required_params JSON COMMENT 'JSON object of required parameters',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the profile was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the profile was last updated'
);

-- NVR Table
CREATE TABLE NVR (
    nvr_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the NVR',
    model VARCHAR(255) NOT NULL COMMENT 'Model of the NVR',
    serial_number VARCHAR(255) NOT NULL UNIQUE COMMENT 'Unique serial number of the NVR',
    firmware_version VARCHAR(50) COMMENT 'Firmware version installed on the NVR',
    storage_capacity_gb INT COMMENT 'Storage capacity of the NVR in gigabytes',
    login_username VARCHAR(255) NOT NULL COMMENT 'Username for accessing the NVR',
    login_password_ref VARCHAR(255) NOT NULL COMMENT 'Reference to the password stored in a secret manager',
    profile_id INT COMMENT 'Reference to NVR configuration profile',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the NVR record was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the NVR record was last updated',
    FOREIGN KEY (profile_id) REFERENCES NVR_Profile(profile_id)
);

-- Camera Table
CREATE TABLE Camera (
    camera_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the camera',
    name VARCHAR(100) NOT NULL COMMENT 'User-defined name for the camera',
    manufacturer_uid VARCHAR(255) NOT NULL UNIQUE COMMENT 'Manufacturer-provided unique ID',
    model VARCHAR(255) NOT NULL COMMENT 'Model of the camera',
    serial_number VARCHAR(255) NOT NULL UNIQUE COMMENT 'Unique serial number of the camera',
    resolution VARCHAR(50) COMMENT 'Resolution of the camera (e.g., 1080p, 4K)',
    status ENUM('online', 'offline', 'unknown') DEFAULT 'unknown' COMMENT 'Current operational status',
    talk_back_support BOOLEAN DEFAULT FALSE COMMENT 'Indicates support for two-way audio',
    night_vision_support BOOLEAN DEFAULT FALSE COMMENT 'Indicates night vision capability',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the camera record was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the camera record was last updated',
    
    -- Performance indexes
    INDEX idx_status (status),
    INDEX idx_manufacturer_model (manufacturer_uid, model)
);

-- TPM_Device Table
CREATE TABLE TPM_Device (
    tmp_device_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the TPM device',
    manufacturer VARCHAR(100) NOT NULL COMMENT 'TPM manufacturer (e.g., Infineon)',
    model VARCHAR(100) NOT NULL COMMENT 'TPM model number',
    serial_number VARCHAR(255) NOT NULL UNIQUE COMMENT 'TPM serial number',
    version VARCHAR(50) NOT NULL COMMENT 'TPM specification version',
    certified BOOLEAN DEFAULT FALSE COMMENT 'Indicates FIPS/CommonCriteria certification',
    supported_algorithms TEXT COMMENT 'Supported cryptographic algorithms',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the TPM record was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the TPM record was last updated'
);

-- Controller Table
CREATE TABLE Controller (
    controller_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the controller',
    type VARCHAR(50) NOT NULL COMMENT 'Type of the controller (e.g., Raspberry Pi)',
    model VARCHAR(255) NOT NULL COMMENT 'Model of the controller',
    serial_number VARCHAR(255) NOT NULL UNIQUE COMMENT 'Unique serial number of the controller',
    os_architecture ENUM('arm32', 'arm64', 'x86', 'x64', 'riscv') NOT NULL COMMENT 'OS processor architecture',
    hw_encryption_enabled BOOLEAN DEFAULT FALSE COMMENT 'Indicates hardware encryption support',
    sw_encryption_enabled BOOLEAN DEFAULT FALSE COMMENT 'Indicates software encryption activation',
    tmp_device_id INT COMMENT 'Reference to TPM security device',
    firmware_version VARCHAR(50) COMMENT 'Firmware version installed on the controller',
    reset_password_ref VARCHAR(255) NOT NULL COMMENT 'Reference to reset password in secret manager',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the controller record was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the controller record was last updated',
    FOREIGN KEY (tmp_device_id) REFERENCES TPM_Device(tmp_device_id),
    
    -- Performance indexes
    INDEX idx_type_model (type, model),
    INDEX idx_serial (serial_number)
);

-- VPN_Config Table
CREATE TABLE VPN_Config (
    vpn_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for VPN configuration',
    name VARCHAR(100) NOT NULL COMMENT 'Configuration name (e.g., "Primary_WireGuard")',
    server_public_key VARCHAR(44) NOT NULL COMMENT 'Base64-encoded server public key',
    server_endpoint VARCHAR(253) NOT NULL COMMENT 'Server IP/FQDN with port',
    allowed_ips JSON NOT NULL COMMENT 'JSON array of allowed CIDR ranges',
    dns_servers JSON COMMENT 'JSON array of DNS server IPs',
    dns_search_domains JSON COMMENT 'JSON array of DNS search domains',
    config_ref VARCHAR(255) COMMENT 'Reference to complete config in storage',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the config was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the config was last updated',
    CHECK (LENGTH(server_public_key) = 44)
);

-- Controller_VPN_Mapping Table
CREATE TABLE Controller_VPN_Mapping (
    mapping_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    controller_id INT NOT NULL UNIQUE COMMENT 'Reference to the controller',
    vpn_id INT NOT NULL COMMENT 'Reference to VPN configuration',
    client_address VARCHAR(43) NOT NULL UNIQUE COMMENT 'Assigned VPN client IP/CIDR (e.g., "10.0.0.2/32")',
    client_public_key VARCHAR(44) NOT NULL COMMENT 'Base64-encoded client public key',
    client_private_key_ref VARCHAR(255) NOT NULL COMMENT 'Reference to client private key in secret manager',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (controller_id) REFERENCES Controller(controller_id),
    FOREIGN KEY (vpn_id) REFERENCES VPN_Config(vpn_id),
    CHECK (LENGTH(client_public_key) = 44),
    CHECK (client_address REGEXP '^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$')
);

-- Contract_NVR_Mapping Table
CREATE TABLE Contract_NVR_Mapping (
    contract_nvr_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    contract_id INT NOT NULL COMMENT 'Reference to the contract',
    nvr_id INT NOT NULL COMMENT 'Reference to the NVR',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (contract_id) REFERENCES Contract(contract_id),
    FOREIGN KEY (nvr_id) REFERENCES NVR(nvr_id)
);

-- NVR_Camera_Mapping Table
CREATE TABLE NVR_Camera_Mapping (
    nvr_camera_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    nvr_id INT NOT NULL COMMENT 'Reference to the NVR',
    camera_id INT NOT NULL COMMENT 'Reference to the camera',
    channel_number INT COMMENT 'Camera channel number on the NVR (1-based)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (nvr_id) REFERENCES NVR(nvr_id),
    FOREIGN KEY (camera_id) REFERENCES Camera(camera_id),
    
    -- Ensure unique channel per NVR
    UNIQUE INDEX idx_nvr_channel (nvr_id, channel_number)
);

-- NVR_Controller_Mapping Table
CREATE TABLE NVR_Controller_Mapping (
    nvr_controller_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    nvr_id INT NOT NULL COMMENT 'Reference to the NVR',
    controller_id INT NOT NULL COMMENT 'Reference to the controller',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (nvr_id) REFERENCES NVR(nvr_id),
    FOREIGN KEY (controller_id) REFERENCES Controller(controller_id)
);

-- Controller_Camera_Support Table
CREATE TABLE Controller_Camera_Support (
    controller_camera_support_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the support mapping',
    controller_id INT NOT NULL COMMENT 'Reference to the controller',
    camera_id INT NOT NULL COMMENT 'Reference to the camera',
    priority INT DEFAULT 1 COMMENT 'Processing priority for this camera. Use cases: 1=Front door/main entrance (highest), 2=Perimeter cameras, 3=Interior cameras, 4=Back areas (lowest). Higher priority cameras get processed first during high load, better resource allocation, and faster response times.',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the support mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the support mapping was last updated',
    FOREIGN KEY (controller_id) REFERENCES Controller(controller_id),
    FOREIGN KEY (camera_id) REFERENCES Camera(camera_id),
    
    -- Ensure unique camera assignment per controller
    UNIQUE INDEX idx_controller_camera (controller_id, camera_id),
    INDEX idx_controller_priority (controller_id, priority)
);

-- SSH_Key Table
CREATE TABLE SSH_Key (
    ssh_key_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the SSH key',
    key_type VARCHAR(50) NOT NULL COMMENT 'Type of the SSH key (e.g., RSA, ED25519)',
    public_key TEXT NOT NULL COMMENT 'SSH public key',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the SSH key was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the SSH key was last updated'
);

-- Controller_SSH_Key_Mapping Table
CREATE TABLE Controller_SSH_Key_Mapping (
    controller_ssh_key_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    controller_id INT NOT NULL COMMENT 'Reference to the controller',
    ssh_key_id INT NOT NULL COMMENT 'Reference to the SSH key',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (controller_id) REFERENCES Controller(controller_id),
    FOREIGN KEY (ssh_key_id) REFERENCES SSH_Key(ssh_key_id)
);

-- X509_Certificate Table
CREATE TABLE X509_Certificate (
    certificate_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the certificate',
    common_name VARCHAR(255) NOT NULL COMMENT 'Common name of the certificate',
    issuer VARCHAR(255) NOT NULL COMMENT 'Issuer of the certificate',
    valid_from DATE NOT NULL COMMENT 'Date when the certificate becomes valid',
    valid_to DATE NOT NULL COMMENT 'Date when the certificate expires',
    certificate_data TEXT NOT NULL COMMENT 'PEM-encoded certificate data',
    private_key_ref VARCHAR(255) NOT NULL COMMENT 'Reference to the private key stored in a secret manager',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the certificate was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the certificate was last updated',
    
    -- Performance index for certificate expiry monitoring
    INDEX idx_valid_to (valid_to)
);

-- Controller_Certificate_Mapping Table
CREATE TABLE Controller_Certificate_Mapping (
    controller_certificate_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the mapping',
    controller_id INT NOT NULL COMMENT 'Reference to the controller',
    certificate_id INT NOT NULL COMMENT 'Reference to the certificate',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Timestamp when the mapping was last updated',
    FOREIGN KEY (controller_id) REFERENCES Controller(controller_id),
    FOREIGN KEY (certificate_id) REFERENCES X509_Certificate(certificate_id)
);

-- ========================================
-- UNIFIED EVENT SYSTEM WITH ADVANCED INCIDENT TRACKING
-- ========================================

CREATE TABLE Security_Event (
    event_id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for all security events',
    contract_id INT NOT NULL COMMENT 'Contract associated with this event',
    camera_id INT NULL COMMENT 'Camera involved (NULL for controller-level events)',
    controller_id INT NOT NULL COMMENT 'Controller that detected/handled the event',
    
    -- Advanced Incident Tracking for Related Events
    parent_event_id BIGINT NULL COMMENT 'Reference to parent event for incident grouping. NULL for root events.',
    incident_id VARCHAR(50) NULL COMMENT 'Shared incident identifier for grouping related events (e.g., INC-20250526-00001)',
    auto_generated_incident BOOLEAN DEFAULT TRUE COMMENT 'Whether incident_id was auto-generated or manually assigned',
    
    -- Event Classification
    event_category ENUM(
        'security',        -- Person detection, intrusion, emergency
        'system',          -- Device offline, network issues, configuration
        'operational',     -- Talk-back, monitoring actions, maintenance
        'alert',          -- Notifications, escalations
        'jamming'         -- Signal jamming and RF interference detection
    ) NOT NULL COMMENT 'High-level event category',
    
    event_type ENUM(
        -- Security Events (often root events)
        'person_detection', 'motion_detection', 'intrusion_alarm', 'emergency_button',
        -- System Events  
        'controller_offline', 'controller_online', 'camera_offline', 'camera_online',
        'network_issue', 'wifi_jamming', 'low_storage', 'firmware_update',
        -- Operational Events (often sub-events)
        'talk_back_initiated', 'talk_back_ended', 'monitoring_acknowledged', 
        'police_contacted', 'customer_notified', 'maintenance_started',
        -- Alert Events (often sub-events)
        'notification_sent', 'escalation_triggered', 'sla_breach',
        -- Signal Jamming Events (can be root events)
        'rf_jamming_detected', 'frequency_interference', 'signal_threshold_exceeded'
    ) NOT NULL COMMENT 'Specific event type',
    
    severity ENUM('info', 'warning', 'critical') NOT NULL COMMENT 'Event severity level',
    
    -- Event Status (for events requiring action)
    status ENUM('new', 'acknowledged', 'in_progress', 'resolved', 'false_positive') DEFAULT 'new' COMMENT 'Current event status',
    
    -- Event Details
    title VARCHAR(255) NOT NULL COMMENT 'Human-readable event title',
    description TEXT COMMENT 'Detailed event description',
    metadata JSON COMMENT 'Event-specific data (AI confidence, coordinates, user_id for actions, response_time_seconds, frequency_data for jamming events, etc.)',
    
    -- Media & Evidence
    video_url VARCHAR(512) COMMENT 'URL to associated video footage if saved',
    image_url VARCHAR(512) COMMENT 'URL to snapshot/thumbnail if available',
    audio_url VARCHAR(512) COMMENT 'URL to audio recording if applicable',
    
    -- Timestamps
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the actual event occurred',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When record was created in DB',
    acknowledged_at TIMESTAMP NULL COMMENT 'When event was acknowledged',
    resolved_at TIMESTAMP NULL COMMENT 'When event was resolved',
    
    -- Foreign Keys
    FOREIGN KEY (contract_id) REFERENCES Contract(contract_id),
    FOREIGN KEY (camera_id) REFERENCES Camera(camera_id),
    FOREIGN KEY (controller_id) REFERENCES Controller(controller_id),
    FOREIGN KEY (parent_event_id) REFERENCES Security_Event(event_id),
    
    -- Performance indexes for timeline queries
    INDEX idx_contract_timestamp (contract_id, event_timestamp DESC),
    INDEX idx_controller_timestamp (controller_id, event_timestamp DESC),
    INDEX idx_camera_timestamp (camera_id, event_timestamp DESC),
    INDEX idx_category_timestamp (event_category, event_timestamp DESC),
    INDEX idx_status_severity (status, severity),
    INDEX idx_timeline_view (contract_id, event_timestamp DESC, event_category, severity),
    
    -- Incident tracking indexes
    INDEX idx_parent_event (parent_event_id),
    INDEX idx_incident_id (incident_id),
    INDEX idx_incident_timeline (incident_id, event_timestamp ASC),
    INDEX idx_auto_incident (auto_generated_incident, event_timestamp DESC)
);

-- Event_Type_Rules Table
CREATE TABLE Event_Type_Rules (
    rule_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for the rule',
    event_type ENUM(
        -- Security Events (often root events)
        'person_detection', 'motion_detection', 'intrusion_alarm', 'emergency_button',
        -- System Events  
        'controller_offline', 'controller_online', 'camera_offline', 'camera_online',
        'network_issue', 'wifi_jamming', 'low_storage', 'firmware_update',
        -- Operational Events (often sub-events)
        'talk_back_initiated', 'talk_back_ended', 'monitoring_acknowledged', 
        'police_contacted', 'customer_notified', 'maintenance_started',
        -- Alert Events (often sub-events)
        'notification_sent', 'escalation_triggered', 'sla_breach',
        -- Signal Jamming Events (can be root events)
        'rf_jamming_detected', 'frequency_interference', 'signal_threshold_exceeded'
    ) NOT NULL COMMENT 'Event type this rule applies to',
    can_be_root BOOLEAN DEFAULT TRUE COMMENT 'Whether this event type can be a root event',
    force_sub_event BOOLEAN DEFAULT FALSE COMMENT 'Whether this event should always be a sub-event',
    auto_combine_window_minutes INT DEFAULT 5 COMMENT 'Time window for auto-combining related events (minutes)',
    default_severity ENUM('info', 'warning', 'critical') COMMENT 'Default severity for this event type',
    description TEXT COMMENT 'Business rule description and rationale',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_event_type (event_type)
);

-- ========================================
-- RF SIGNAL JAMMING DETECTION SYSTEM
-- ========================================

-- RF_Frequency_Profile Table
CREATE TABLE RF_Frequency_Profile (
    frequency_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for frequency profile',
    frequency_mhz DECIMAL(8,3) NOT NULL COMMENT 'Frequency in MHz (e.g., 433.920 for 433.92 MHz)',
    frequency_name VARCHAR(100) NOT NULL COMMENT 'Human-readable name (e.g., "433 MHz ISM Band")',
    description TEXT COMMENT 'Detailed description of frequency usage and importance',
    category ENUM(
        'security_system',    -- Security system frequencies (door sensors, motion detectors)
        'home_automation',    -- Smart home devices, IoT sensors
        'garage_door',       -- Garage door openers
        'car_remote',        -- Car key fobs and remote controls
        'wifi',              -- Wi-Fi channels and bands
        'bluetooth',         -- Bluetooth communication
        'cellular',          -- Cellular network bands
        'emergency',         -- Emergency services frequencies
        'industrial',        -- Industrial IoT and monitoring
        'custom'            -- Customer-specific frequencies
    ) NOT NULL COMMENT 'Frequency category for organization',
    
    -- Default monitoring thresholds (can be overridden per customer)
    default_threshold_dbm DECIMAL(5,2) NOT NULL COMMENT 'Default signal strength threshold in dBm (e.g., -60.00)',
    default_enabled BOOLEAN DEFAULT TRUE COMMENT 'Whether this frequency is monitored by default for new customers',
    
    -- Frequency specifications
    bandwidth_khz INT COMMENT 'Expected bandwidth in kHz for this frequency',
    modulation_type VARCHAR(50) COMMENT 'Expected modulation type (AM, FM, FSK, etc.)',
    typical_usage TEXT COMMENT 'What devices typically use this frequency',
    
    -- Risk assessment
    security_importance ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium' COMMENT 'Security importance of this frequency',
    jamming_risk ENUM('low', 'medium', 'high') DEFAULT 'medium' COMMENT 'Likelihood of this frequency being targeted for jamming',
    
    active BOOLEAN DEFAULT TRUE COMMENT 'Whether this frequency profile is active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_frequency (frequency_mhz),
    INDEX idx_category (category),
    INDEX idx_security_importance (security_importance),
    INDEX idx_default_enabled (default_enabled)
);

-- Contract_RF_Monitoring Table  
CREATE TABLE Contract_RF_Monitoring (
    contract_rf_id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'Unique identifier for contract RF monitoring',
    contract_id INT NOT NULL COMMENT 'Reference to the contract',
    frequency_id INT NOT NULL COMMENT 'Reference to RF frequency profile',
    
    -- Customer-specific overrides
    enabled BOOLEAN DEFAULT TRUE COMMENT 'Whether monitoring is enabled for this frequency for this customer',
    custom_threshold_dbm DECIMAL(5,2) COMMENT 'Customer-specific threshold override (NULL = use default)',
    alert_level ENUM('info', 'warning', 'critical') COMMENT 'Alert level override (NULL = use frequency default)',
    
    -- Monitoring configuration
    scan_interval_seconds INT DEFAULT 60 COMMENT 'How often to scan this frequency (seconds)',
    alert_cooldown_minutes INT DEFAULT 15 COMMENT 'Minimum time between alerts for this frequency',
    
    -- Customer notes
    customer_notes TEXT COMMENT 'Customer-specific notes about this frequency monitoring',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (contract_id) REFERENCES Contract(contract_id),
    FOREIGN KEY (frequency_id) REFERENCES RF_Frequency_Profile(frequency_id),
    
    UNIQUE INDEX idx_contract_frequency (contract_id, frequency_id),
    INDEX idx_contract_enabled (contract_id, enabled),
    INDEX idx_frequency_enabled (frequency_id, enabled)
);

-- =========================================
-- CUSTOMER DATA ACCESS VIEWS
-- These views provide secure, scoped access to customer data
-- =========================================

-- Customer's contracts with current service tier
CREATE VIEW Customer_Contracts_View AS
SELECT 
    ccm.customer_id,
    c.contract_id,
    c.service_address,
    c.notification_email,
    c.notification_phone,
    c.start_date,
    c.end_date,
    c.created_at,
    c.updated_at,
    st.service_tier_id,
    st.name as service_tier_name,
    st.description as service_tier_description,
    cst.start_date as tier_start_date,
    cst.end_date as tier_end_date
FROM Contract c
JOIN Contract_Customer_Mapping ccm ON c.contract_id = ccm.contract_id
LEFT JOIN Contract_Service_Tier cst ON c.contract_id = cst.contract_id
    AND cst.start_date <= CURDATE()
    AND cst.end_date >= CURDATE()
LEFT JOIN Service_Tier st ON cst.service_tier_id = st.service_tier_id
WHERE c.start_date <= CURDATE() AND c.end_date >= CURDATE();

-- Customer's equipment overview (NVRs, Controllers, Cameras)
CREATE VIEW Customer_Equipment_View AS
SELECT 
    ccm.customer_id,
    c.contract_id,
    c.service_address,
    -- NVR Information
    n.nvr_id,
    n.model as nvr_model,
    n.serial_number as nvr_serial,
    n.firmware_version as nvr_firmware,
    n.storage_capacity_gb,
    -- Controller Information
    ctrl.controller_id,
    ctrl.type as controller_type,
    ctrl.model as controller_model,
    ctrl.serial_number as controller_serial,
    ctrl.firmware_version as controller_firmware,
    ctrl.os_architecture,
    ctrl.hw_encryption_enabled,
    ctrl.sw_encryption_enabled,
    -- Camera Information
    cam.camera_id,
    cam.name as camera_name,
    cam.model as camera_model,
    cam.serial_number as camera_serial,
    cam.resolution,
    cam.status as camera_status,
    cam.talk_back_support,
    cam.night_vision_support,
    ccs.priority as camera_priority,
    ncm_map.channel_number
FROM Contract c
JOIN Contract_Customer_Mapping ccm ON c.contract_id = ccm.contract_id
JOIN Contract_NVR_Mapping cnm ON c.contract_id = cnm.contract_id
JOIN NVR n ON cnm.nvr_id = n.nvr_id
JOIN NVR_Controller_Mapping ncm ON n.nvr_id = ncm.nvr_id
JOIN Controller ctrl ON ncm.controller_id = ctrl.controller_id
JOIN Controller_Camera_Support ccs ON ctrl.controller_id = ccs.controller_id
JOIN Camera cam ON ccs.camera_id = cam.camera_id
LEFT JOIN NVR_Camera_Mapping ncm_map ON n.nvr_id = ncm_map.nvr_id AND cam.camera_id = ncm_map.camera_id
WHERE c.start_date <= CURDATE() AND c.end_date >= CURDATE();

-- Customer's RF Monitoring configuration
CREATE VIEW Customer_RF_Monitoring_View AS
SELECT 
    ccm.customer_id,
    c.contract_id,
    c.service_address,
    crm.contract_rf_id,
    crm.enabled as monitoring_enabled,
    fp.frequency_id,
    fp.frequency_mhz,
    fp.frequency_name,
    fp.description as frequency_description,
    fp.category,
    fp.typical_usage,
    fp.security_importance,
    fp.jamming_risk,
    COALESCE(crm.custom_threshold_dbm, fp.default_threshold_dbm) as threshold_dbm,
    COALESCE(crm.alert_level, CASE 
        WHEN fp.security_importance = 'critical' THEN 'critical'
        WHEN fp.security_importance = 'high' THEN 'warning'
        ELSE 'info'
    END) as alert_level,
    crm.scan_interval_seconds,
    crm.alert_cooldown_minutes,
    crm.customer_notes
FROM Contract c
JOIN Contract_Customer_Mapping ccm ON c.contract_id = ccm.contract_id
JOIN Contract_RF_Monitoring crm ON c.contract_id = crm.contract_id
JOIN RF_Frequency_Profile fp ON crm.frequency_id = fp.frequency_id
WHERE c.start_date <= CURDATE() AND c.end_date >= CURDATE()
    AND fp.active = TRUE
ORDER BY fp.security_importance DESC, fp.frequency_mhz;

-- Customer dashboard summary view
CREATE VIEW Customer_Dashboard_View AS
SELECT 
    c.customer_id,
    c.name_on_contract,
    c.email,
    c.phone_number,
    COUNT(DISTINCT contracts.contract_id) as total_contracts,
    COUNT(DISTINCT contracts.contract_id) as active_contracts, -- All are active due to date filter
    COUNT(DISTINCT equipment.nvr_id) as total_nvrs,
    COUNT(DISTINCT equipment.controller_id) as total_controllers,
    COUNT(DISTINCT equipment.camera_id) as total_cameras,
    COUNT(DISTINCT CASE WHEN equipment.camera_status = 'online' THEN equipment.camera_id END) as online_cameras,
    COUNT(DISTINCT rf_monitoring.frequency_id) as monitored_frequencies,
    COUNT(DISTINCT CASE WHEN rf_monitoring.monitoring_enabled = TRUE THEN rf_monitoring.frequency_id END) as active_rf_monitors
FROM Customer c
LEFT JOIN Customer_Contracts_View contracts ON c.customer_id = contracts.customer_id
LEFT JOIN Customer_Equipment_View equipment ON c.customer_id = equipment.customer_id
LEFT JOIN Customer_RF_Monitoring_View rf_monitoring ON c.customer_id = rf_monitoring.customer_id
WHERE c.active = TRUE
GROUP BY c.customer_id, c.name_on_contract, c.email, c.phone_number;

-- =========================================
-- STORED PROCEDURES FOR CUSTOMER AUTH
-- =========================================

DELIMITER //

-- Clean expired customer sessions
CREATE PROCEDURE CleanExpiredCustomerSessions()
BEGIN
    DELETE FROM Customer_Session WHERE expires_at < NOW();
END //

DELIMITER ;

-- =========================================
-- CLEANUP EVENTS
-- =========================================

-- Create scheduled event for customer session cleanup
CREATE EVENT IF NOT EXISTS CleanExpiredCustomerSessionsEvent
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanExpiredCustomerSessions();
