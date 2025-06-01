# SenseGuard Security Platform API

[![API Version](https://img.shields.io/badge/API-v1.0.0-blue.svg)](https://admin.dev.senseinfra.cloud/api/v1/)
[![Documentation](https://img.shields.io/badge/docs-complete-green.svg)](./docs/)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://admin.dev.senseinfra.cloud/api/v1/health)

> Comprehensive API for the SenseGuard Security Platform - Managing security systems, hardware monitoring, and real-time event processing.

## 🚀 Quick Start

```bash
# Test the API
curl https://admin.dev.senseinfra.cloud/api/v1/health

# Login and get a token
curl -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SenseGuard2025!"}'
```

**Base URL:** `https://admin.dev.senseinfra.cloud/api/v1/`

## 📚 Documentation

### Core Documentation
- [**API Overview**](./docs/01-overview.md) - Authentication, rate limiting, response formats
- [**Getting Started**](./docs/02-getting-started.md) - Setup, authentication flow, first requests
- [**Error Handling**](./docs/03-error-handling.md) - HTTP status codes, error responses, troubleshooting

### API Endpoints

#### ✅ Implemented Endpoints
- [**Health Check**](./docs/api/health.md) - System monitoring with DDoS protection
- [**Authentication & Users**](./docs/api/auth.md) - User management, JWT tokens, permissions
- [**API Key Management**](./docs/api/api-keys.md) - Programmatic access, usage tracking
- [**Customer Management**](./docs/api/customers.md) - Customer lifecycle management
- [**Contract Management**](./docs/api/contracts.md) - Service contracts and agreements
- [**Diagnostics**](./docs/api/diagnostics.md) - System and database monitoring

#### 🔄 Planned Endpoints (TBD)
- [**Service Tiers**](./docs/api/service-tiers.md) - Gold/Silver/Platinum service levels
- [**Hardware Management**](./docs/api/hardware.md) - NVR, cameras, controllers, TPM devices
- [**Event & Monitoring**](./docs/api/events.md) - Security events, incidents, real-time streaming
- [**RF Monitoring**](./docs/api/rf-monitoring.md) - Frequency monitoring, jamming detection

### Development Resources
- [**Development Guide**](./docs/development/guide.md) - Adding endpoints, database integration
- [**Testing Guide**](./docs/development/testing.md) - API testing, examples, automation
- [**Security Guide**](./docs/development/security.md) - Best practices, authentication flows
- [**Database Schema**](./docs/development/database.md) - Complete schema documentation

### Reference
- [**API Reference**](./docs/reference/endpoints.md) - Complete endpoint listing
- [**Error Codes**](./docs/reference/errors.md) - Detailed error reference
- [**Changelog**](./docs/reference/changelog.md) - Version history and roadmap

## 🏗️ Implementation Status

| Component | Status | Endpoints | Documentation |
|-----------|--------|-----------|---------------|
| Health Check | ✅ Complete | 1 | [📖](./docs/api/health.md) |
| Authentication | ✅ Complete | 8 | [📖](./docs/api/auth.md) |
| API Keys | ✅ Complete | 6 | [📖](./docs/api/api-keys.md) |
| Customers | ✅ Complete | 5 | [📖](./docs/api/customers.md) |
| Contracts | ✅ Complete | 5 | [📖](./docs/api/contracts.md) |
| Diagnostics | ✅ Complete | 2 | [📖](./docs/api/diagnostics.md) |
| Service Tiers | 🔄 Planned | 7 | [📖](./docs/api/service-tiers.md) |
| Hardware | 🔄 Planned | 25+ | [📖](./docs/api/hardware.md) |
| Events | 🔄 Planned | 12 | [📖](./docs/api/events.md) |
| RF Monitoring | 🔄 Planned | 15 | [📖](./docs/api/rf-monitoring.md) |

**Total: 27 implemented, 59+ planned endpoints**

## 🛡️ Security Features

- **JWT Authentication** with role-based access control
- **API Key Management** with usage tracking and expiration
- **Rate Limiting** to prevent DDoS attacks (10 req/min health, 5 req/min login)
- **Input Validation** and SQL injection prevention
- **Audit Logging** for all API operations
- **HTTPS Enforcement** in production environments

## 🏆 Key Features

### Current Capabilities
- ✅ **Health Monitoring** - Cached health checks prevent DB overload
- ✅ **User Management** - Complete RBAC with granular permissions  
- ✅ **Customer & Contracts** - Full business entity management
- ✅ **API Keys** - Secure programmatic access with usage analytics
- ✅ **Rate Limiting** - DDoS protection on public endpoints

### Planned Capabilities
- 🔄 **Hardware Management** - NVR, cameras, controllers, TPM devices
- 🔄 **Event Processing** - Real-time security event handling
- 🔄 **RF Monitoring** - 46+ frequency monitoring with jamming detection
- 🔄 **Service Tiers** - Tiered service offerings (Silver, Gold, Platinum)
- 🔄 **Real-time Streaming** - WebSocket event feeds

## 📊 Database Integration

The API is built on a comprehensive MySQL schema with 25+ tables:

### Core Tables
- `Customer`, `Contract` - Business entities ✅
- `Service_Tier`, `Contract_Service_Tier` - Service levels 🔄
- `System_User`, `User_Role`, `API_Key` - Authentication ✅

### Hardware Tables  
- `NVR`, `Camera`, `Controller` - Physical devices 🔄
- `TPM_Device`, `VPN_Config` - Security infrastructure 🔄
- `SSH_Key`, `X509_Certificate` - Access management 🔄

### Event Tables
- `Security_Event`, `Event_Type_Rules` - Event processing 🔄
- `RF_Frequency_Profile`, `Contract_RF_Monitoring` - RF monitoring 🔄

See [Database Schema Documentation](./docs/development/database.md) for complete details.

## 🚦 Implementation Roadmap

### Phase 1: Foundation ✅ (Complete)
- Health monitoring with caching
- User authentication and management  
- API key management with usage tracking
- Customer and contract management
- Rate limiting and security features

### Phase 2: Service Management 🔄 (Q2 2025)
- Service tier management
- NVR profile configuration
- Basic hardware device registration

### Phase 3: Hardware Integration 🔄 (Q3 2025)
- Complete hardware management (NVR, cameras, controllers)
- Basic event logging
- TPM and certificate management

### Phase 4: Advanced Features 🔄 (Q4 2025)
- Advanced event and incident management
- RF frequency monitoring
- Signal jamming detection

### Phase 5: Enterprise Features 🔄 (Q1 2026)
- Real-time event streaming via WebSocket
- Advanced analytics and reporting
- Spectrum analysis capabilities

## 🧪 Testing

```bash
# Test health endpoint with rate limiting
for i in {1..15}; do curl https://admin.dev.senseinfra.cloud/api/v1/health; echo " - Request $i"; done

# Test authentication
TOKEN=$(curl -s -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SenseGuard2025!"}' | jq -r '.token')

# Test authenticated endpoint
curl -H "Authorization: Bearer $TOKEN" https://admin.dev.senseinfra.cloud/api/v1/auth/profile
```

See [Testing Guide](./docs/development/testing.md) for comprehensive testing examples.

## 📞 Support

- **Documentation:** [GitHub Repository](https://github.com/sense-infra/admin-backend)
- **Issues:** [GitHub Issues](https://github.com/sense-infra/admin-backend/issues)
- **Email:** info@senseguard.cloud
- **Status:** [System Status](https://status.senseinfra.cloud)

## 📄 License

Copyright © 2025 SenseGuard. All rights reserved.

---

**API Version:** 1.0.0 | **Documentation:** 1.0.0 | **Last Updated:** January 1, 2025
