-- =========================================
-- SENSE SECURITY PLATFORM - DATA INSERTS
-- Sample Data and RF Frequency Profiles
-- =========================================

-- ========================================
-- RF FREQUENCY PROFILES DATA
-- ========================================
-- Pre-populated frequency profiles for common security and IoT devices
-- Load this data immediately after creating the schema

INSERT INTO RF_Frequency_Profile (
    frequency_mhz, frequency_name, description, category, 
    default_threshold_dbm, bandwidth_khz, typical_usage, 
    security_importance, jamming_risk
) VALUES 
-- Emergency Services (monitoring for interference)
(155.000, '155 MHz Emergency Services', 'Emergency services communication band', 'emergency', -60.00, 25, 'Police, fire, EMS communications', 'critical', 'low'),

-- Remote Controls and Security Systems (Low Frequencies)
(310.000, '310 MHz Remote Controls', 'Remote control frequency for gates and access systems', 'security_system', -75.00, 20, 'Gate openers, access control remotes, panic buttons', 'medium', 'medium'),

(315.000, '315 MHz Security Band', 'Common frequency for door/window sensors, motion detectors, and security system components in North America', 'security_system', -70.00, 20, 'Door sensors, window sensors, motion detectors, security keypads', 'critical', 'high'),

(318.000, '318 MHz Car Remote', 'Car key fob and remote control frequency', 'car_remote', -75.00, 20, 'Car key fobs, remote car starters', 'medium', 'medium'),

(319.500, '319.5 MHz Home Automation', 'Home automation and wireless sensor frequency', 'home_automation', -70.00, 25, 'Wireless thermostats, smart switches, environmental sensors', 'medium', 'low'),

(345.000, '345 MHz Industrial Remote', 'Industrial remote control frequency', 'industrial', -70.00, 20, 'Industrial equipment remotes, crane controls, gate operators', 'low', 'low'),

(390.000, '390 MHz Garage Door', 'Common garage door opener frequency', 'garage_door', -75.00, 20, 'Garage door openers, gate controllers', 'medium', 'medium'),

(418.000, '418 MHz Security Systems', 'Alternative security system frequency used in some regions', 'security_system', -70.00, 25, 'Security sensors, alarm systems, monitoring devices', 'high', 'medium'),

(433.920, '433.92 MHz ISM Band', 'European ISM band used for security devices, garage doors, and remote controls', 'security_system', -70.00, 25, 'European security sensors, garage door openers, car remotes, weather stations', 'critical', 'high'),

(868.000, '868 MHz SRD Band', 'European Short Range Device band for security and automation', 'security_system', -65.00, 25, 'European security systems, smart home devices, IoT sensors', 'high', 'medium'),

(868.420, 'Z-Wave (EU)', 'Z-Wave home automation protocol frequency (Europe)', 'home_automation', -70.00, 40, 'Z-Wave smart home devices, door locks, sensors', 'medium', 'low'),

(908.420, 'Z-Wave (US)', 'Z-Wave home automation protocol frequency (US)', 'home_automation', -70.00, 40, 'Z-Wave smart home devices, door locks, sensors', 'medium', 'low'),

(915.000, '915 MHz ISM Band', 'North American ISM band for security and industrial applications', 'security_system', -70.00, 26, 'North American security systems, industrial sensors, RFID', 'high', 'medium'),

-- Wi-Fi 2.4 GHz Band
(2412.000, 'Wi-Fi Channel 1 (2.4 GHz)', 'Wi-Fi 2.4 GHz band - Channel 1', 'wifi', -50.00, 22000, 'Wi-Fi networks, security cameras, smart home devices', 'high', 'high'),

(2437.000, 'Wi-Fi Channel 6 (2.4 GHz)', 'Wi-Fi 2.4 GHz band - Channel 6', 'wifi', -50.00, 22000, 'Wi-Fi networks, security cameras, smart home devices', 'high', 'high'),

(2440.000, 'Bluetooth 2.4 GHz', 'Bluetooth communication frequency', 'bluetooth', -60.00, 1000, 'Bluetooth devices, wireless sensors, beacons', 'medium', 'low'),

(2462.000, 'Wi-Fi Channel 11 (2.4 GHz)', 'Wi-Fi 2.4 GHz band - Channel 11', 'wifi', -50.00, 22000, 'Wi-Fi networks, security cameras, smart home devices', 'high', 'high'),

-- Wi-Fi 5 GHz Band (Lower Channels)
(5180.000, 'Wi-Fi Channel 36 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 36', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras, enterprise devices', 'high', 'medium'),

(5200.000, 'Wi-Fi Channel 40 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 40', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras, enterprise devices', 'high', 'medium'),

(5220.000, 'Wi-Fi Channel 44 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 44', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras, enterprise devices', 'high', 'medium'),

(5240.000, 'Wi-Fi Channel 48 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 48', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras, enterprise devices', 'high', 'medium'),

-- Wi-Fi 5 GHz Band (DFS Channels)
(5260.000, 'Wi-Fi Channel 52 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 52 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5280.000, 'Wi-Fi Channel 56 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 56 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5300.000, 'Wi-Fi Channel 60 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 60 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5320.000, 'Wi-Fi Channel 64 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 64 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5500.000, 'Wi-Fi Channel 100 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 100 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5520.000, 'Wi-Fi Channel 104 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 104 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5540.000, 'Wi-Fi Channel 108 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 108 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5560.000, 'Wi-Fi Channel 112 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 112 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5580.000, 'Wi-Fi Channel 116 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 116 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5600.000, 'Wi-Fi Channel 120 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 120 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5620.000, 'Wi-Fi Channel 124 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 124 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5640.000, 'Wi-Fi Channel 128 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 128 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5660.000, 'Wi-Fi Channel 132 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 132 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5680.000, 'Wi-Fi Channel 136 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 136 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

(5700.000, 'Wi-Fi Channel 140 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 140 (DFS)', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, radar detection required', 'medium', 'low'),

-- Wi-Fi 5 GHz Band (Upper Channels)
(5745.000, 'Wi-Fi Channel 149 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 149', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras', 'high', 'medium'),

(5765.000, 'Wi-Fi Channel 153 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 153', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras', 'high', 'medium'),

(5785.000, 'Wi-Fi Channel 157 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 157', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras', 'high', 'medium'),

(5805.000, 'Wi-Fi Channel 161 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 161', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras', 'high', 'medium'),

(5825.000, 'Wi-Fi Channel 165 (5 GHz)', 'Wi-Fi 5 GHz band - Channel 165', 'wifi', -55.00, 20000, '5GHz Wi-Fi networks, high-bandwidth security cameras', 'high', 'medium');

-- =========================================
-- SAMPLE DATA FOR TESTING (COMMENTED OUT)
-- =========================================
-- Uncomment sections below during development/testing as needed

/*
-- Sample Service Tiers
INSERT INTO Service_Tier (name, description, config) VALUES 
('Silver', 'Basic monitoring with standard response', '{"video_retention_days": 30, "response_time_minutes": 15, "priority_level": 1, "max_rf_frequencies": 5, "allowed_rf_categories": ["security_system"]}'),
('Gold', 'Premium monitoring with priority response', '{"video_retention_days": 90, "response_time_minutes": 5, "priority_level": 2, "max_rf_frequencies": 15, "allowed_rf_categories": ["security_system", "wifi", "garage_door", "car_remote"]}'),
('Platinum', 'Enterprise monitoring with immediate response', '{"video_retention_days": 365, "response_time_minutes": 2, "priority_level": 3, "max_rf_frequencies": -1, "allowed_rf_categories": ["all"], "custom_frequencies_allowed": true}');

-- Sample NVR Profiles
INSERT INTO NVR_Profile (name, manufacturer, api_type, auth_type, stream_config, event_config) VALUES 
('Dahua-8CH-4K', 'Dahua', 'ONVIF', 'Digest', 
 '{"main_stream": {"resolution": "4K", "fps": 15, "bitrate": "4Mbps"}, "sub_stream": {"resolution": "720p", "fps": 10, "bitrate": "1Mbps"}}',
 '{"motion_detection": true, "line_crossing": true, "intrusion_detection": true}'),
('Hikvision-16CH-HD', 'Hikvision', 'ONVIF', 'Basic',
 '{"main_stream": {"resolution": "1080p", "fps": 20, "bitrate": "2Mbps"}, "sub_stream": {"resolution": "480p", "fps": 15, "bitrate": "512Kbps"}}',
 '{"motion_detection": true, "face_detection": false, "vehicle_detection": true}');
*/

/*
-- Event Type Rules (Business Logic for Incident Management  
INSERT INTO Event_Type_Rules (event_type, can_be_root, force_sub_event, auto_combine_window_minutes, default_severity, description) VALUES 
-- Root events (primary incidents)
('person_detection', TRUE, FALSE, 5, 'warning', 'Person detection can be root event - often triggers monitoring response'),
('motion_detection', TRUE, FALSE, 3, 'info', 'Motion detection can be root event but often combined with person detection'),
('intrusion_alarm', TRUE, FALSE, 10, 'critical', 'Intrusion alarms are always root events - highest priority'),
('emergency_button', TRUE, FALSE, 15, 'critical', 'Emergency button activation is always a root event'),
('controller_offline', TRUE, FALSE, 30, 'critical', 'Controller offline is root event - indicates system failure'),
('camera_offline', TRUE, FALSE, 15, 'warning', 'Camera offline can be root event unless part of larger system issue'),
('network_issue', TRUE, FALSE, 10, 'warning', 'Network issues can be root events or combined with device offline events'),
('rf_jamming_detected', TRUE, FALSE, 5, 'critical', 'RF jamming is always a root event - indicates active attack'),
('frequency_interference', TRUE, FALSE, 5, 'warning', 'Frequency interference can be root event or sub-event of jamming'),

-- Sub-events (always follow-up actions)
('talk_back_initiated', FALSE, TRUE, 0, 'info', 'Talk-back is always a response to another event - never standalone'),
('talk_back_ended', FALSE, TRUE, 0, 'info', 'Talk-back end is always a sub-event following talk-back start'),
('monitoring_acknowledged', FALSE, TRUE, 0, 'info', 'Acknowledgment is always a response to a primary event'),
('police_contacted', FALSE, TRUE, 0, 'warning', 'Police contact is always a response action - never standalone'),
('customer_notified', FALSE, TRUE, 0, 'info', 'Customer notification is always a response action'),
('notification_sent', FALSE, TRUE, 0, 'info', 'Notification sending is always a sub-event'),
('escalation_triggered', FALSE, TRUE, 0, 'warning', 'Escalation is always a response to unresolved primary event'),

-- Flexible events (can be root or sub depending on context)
('controller_online', TRUE, FALSE, 5, 'info', 'Controller online can be root (recovery) or sub (after offline incident)'),
('camera_online', TRUE, FALSE, 5, 'info', 'Camera online can be root (recovery) or sub (after offline incident)'),
('maintenance_started', TRUE, FALSE, 60, 'info', 'Maintenance can be root (scheduled) or sub (reactive to issues)'),
('firmware_update', TRUE, FALSE, 30, 'info', 'Firmware update can be root (scheduled) or sub (fix for issues)'),
('sla_breach', FALSE, TRUE, 0, 'critical', 'SLA breach is always a consequence of delayed response to primary event');
*/

-- =========================================
-- RF MONITORING USAGE EXAMPLES
-- =========================================

/*
-- Example 1: Customer wants to monitor only 433 MHz with custom threshold
INSERT INTO Contract_RF_Monitoring (contract_id, frequency_id, enabled, custom_threshold_dbm, customer_notes)
SELECT 1, frequency_id, true, -65.00, 'Customer has 433MHz garage door opener - monitor for jamming attacks'
FROM RF_Frequency_Profile WHERE frequency_mhz = 433.920;

-- Example 2: Enable all security-critical frequencies for a customer
INSERT INTO Contract_RF_Monitoring (contract_id, frequency_id, enabled, alert_level)
SELECT 1, frequency_id, true, 'critical'
FROM RF_Frequency_Profile 
WHERE security_importance = 'critical' AND default_enabled = true;

-- Example 3: Get monitoring configuration for a customer
SELECT 
    rfp.frequency_mhz,
    rfp.frequency_name,
    rfp.category,
    COALESCE(crm.custom_threshold_dbm, rfp.default_threshold_dbm) as threshold_dbm,
    COALESCE(crm.alert_level, CASE rfp.security_importance 
        WHEN 'critical' THEN 'critical'
        WHEN 'high' THEN 'warning' 
        ELSE 'info' END) as alert_level,
    crm.scan_interval_seconds,
    rfp.typical_usage
FROM RF_Frequency_Profile rfp
LEFT JOIN Contract_RF_Monitoring crm ON rfp.frequency_id = crm.frequency_id AND crm.contract_id = ?
WHERE (crm.enabled = true OR (crm.contract_rf_id IS NULL AND rfp.default_enabled = true))
ORDER BY rfp.security_importance DESC, rfp.frequency_mhz;

-- Example 4: RTL-SDR Detection Event
INSERT INTO Security_Event (
    controller_id, contract_id, incident_id,
    event_category, event_type, severity,
    title, description, metadata
) VALUES (
    1, 1, 'INC-20250526-00001',
    'jamming', 'rf_jamming_detected', 'critical',
    'RF Jamming detected on 433.92 MHz',
    'Signal strength spike detected on 433MHz ISM band - possible jamming attack',
    '{
        "frequency_mhz": 433.920,
        "signal_strength_dbm": -45.2,
        "threshold_dbm": -70.0,
        "duration_seconds": 120,
        "bandwidth_affected_khz": 50,
        "rtl_sdr_device_id": "rtl_001"
    }'
);
*/
