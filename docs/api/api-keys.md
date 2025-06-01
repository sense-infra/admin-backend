# API Key Management

Secure programmatic access with usage tracking and comprehensive management capabilities.

## Overview

**Base Endpoints:** `/auth/api-keys/*`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:read`, `api_keys:create`, `api_keys:update`, `api_keys:delete`

## Quick Start

```bash
# 1. Get admin token
TOKEN=$(curl -s -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SenseGuard2025!"}' | jq -r '.token')

# 2. Create API key
API_KEY=$(curl -s -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_name":"My API Key","description":"Test key"}' | jq -r '.api_key')

# 3. Use API key for requests
curl -H "X-API-Key: $API_KEY" \
  https://admin.dev.senseinfra.cloud/api/v1/customers
```

## API Key Management

### List API Keys

**Endpoint:** `GET /auth/api-keys`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:read`

**Response:**
```json
[
  {
    "id": 1,
    "key_name": "Production API Key",
    "key_prefix": "sk_prod_1234",
    "created_by_user": {
      "id": 1,
      "username": "admin"
    },
    "usage_count": 1543,
    "last_used": "2025-01-01T12:00:00Z",
    "active": true,
    "expires_at": "2025-12-31T23:59:59Z",
    "created_at": "2025-01-01T00:00:00Z"
  },
  {
    "id": 2,
    "key_name": "Development Key",
    "key_prefix": "sk_dev_5678",
    "created_by_user": {
      "id": 1,
      "username": "admin"
    },
    "usage_count": 245,
    "last_used": "2025-01-01T11:30:00Z",
    "active": true,
    "expires_at": null,
    "created_at": "2025-01-01T06:00:00Z"
  }
]
```

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys
```

### Get API Key by ID

**Endpoint:** `GET /auth/api-keys/{id}`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:read`

**Parameters:**
- `id` (path) - API Key ID

**Response:**
```json
{
  "id": 1,
  "key_name": "Production API Key",
  "key_prefix": "sk_prod_1234",
  "description": "Main production API key for external integrations",
  "created_by_user": {
    "id": 1,
    "username": "admin",
    "email": "admin@senseinfra.cloud"
  },
  "permissions": {
    "customers": ["read", "create", "update"],
    "contracts": ["read"]
  },
  "rate_limit_per_hour": 1000,
  "usage_count": 1543,
  "last_used": "2025-01-01T12:00:00Z",
  "active": true,
  "expires_at": "2025-12-31T23:59:59Z",
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T08:00:00Z"
}
```

### Create API Key

**Endpoint:** `POST /auth/api-keys`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:create`

**Request:**
```json
{
  "key_name": "Integration API Key",
  "description": "API key for third-party integration",
  "expires_at": "2025-12-31T23:59:59Z",
  "permissions": {
    "customers": ["read"],
    "contracts": ["read"]
  },
  "rate_limit_per_hour": 500
}
```

**Response:**
```json
{
  "id": 3,
  "key_name": "Integration API Key",
  "api_key": "sk_prod_abcd1234567890efgh...",
  "key_prefix": "sk_prod_abcd",
  "description": "API key for third-party integration",
  "permissions": {
    "customers": ["read"],
    "contracts": ["read"]
  },
  "rate_limit_per_hour": 500,
  "expires_at": "2025-12-31T23:59:59Z",
  "active": true,
  "created_at": "2025-01-01T12:00:00Z"
}
```

⚠️ **Important:** The full API key is only shown once during creation. Store it securely.

**Example:**
```bash
curl -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "Test API Key",
    "description": "Testing purposes",
    "expires_at": "2025-12-31T23:59:59Z"
  }'
```

### Update API Key

**Endpoint:** `PUT /auth/api-keys/{id}`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:update`

**Request:**
```json
{
  "key_name": "Updated API Key Name",
  "description": "Updated description",
  "active": false,
  "rate_limit_per_hour": 2000
}
```

**Response:**
```json
{
  "id": 1,
  "key_name": "Updated API Key Name",
  "key_prefix": "sk_prod_1234",
  "description": "Updated description",
  "active": false,
  "rate_limit_per_hour": 2000,
  "updated_at": "2025-01-01T12:30:00Z"
}
```

### Delete API Key

**Endpoint:** `DELETE /auth/api-keys/{id}`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:delete`

**Response:**
```json
{
  "message": "API key deleted successfully"
}
```

**Example:**
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys/3
```

## Usage Analytics

### Get API Key Usage

**Endpoint:** `GET /auth/api-keys/{id}/usage`  
**Authentication:** Required (Admin only)  
**Permissions:** `api_keys:read`

**Query Parameters:**
- `period` (optional) - `day`, `week`, `month` (default: `month`)
- `from_date` (optional) - Start date (ISO 8601)
- `to_date` (optional) - End date (ISO 8601)

**Response:**
```json
{
  "api_key_id": 1,
  "total_requests": 1543,
  "requests_today": 127,
  "requests_this_week": 892,
  "requests_this_month": 1543,
  "last_used": "2025-01-01T12:00:00Z",
  "usage_by_endpoint": [
    {
      "endpoint": "/customers",
      "method": "GET",
      "count": 856,
      "percentage": 55.5
    },
    {
      "endpoint": "/contracts",
      "method": "GET",
      "count": 432,
      "percentage": 28.0
    },
    {
      "endpoint": "/customers",
      "method": "POST",
      "count": 255,
      "percentage": 16.5
    }
  ],
  "usage_by_day": [
    {
      "date": "2025-01-01",
      "requests": 127
    },
    {
      "date": "2024-12-31",
      "requests": 143
    }
  ],
  "rate_limit_hits": 12,
  "error_count": 23,
  "success_rate": 98.5
}
```

**Example:**
```bash
# Get current month usage
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys/1/usage

# Get specific date range
curl -H "Authorization: Bearer $TOKEN" \
  "https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys/1/usage?from_date=2024-12-01&to_date=2024-12-31"
```

## Using API Keys

### Authentication Methods

#### Method 1: X-API-Key Header (Recommended)
```bash
curl -H "X-API-Key: sk_prod_abc123..." \
  https://admin.dev.senseinfra.cloud/api/v1/customers
```

#### Method 2: Authorization Bearer Header
```bash
curl -H "Authorization: Bearer sk_prod_abc123..." \
  https://admin.dev.senseinfra.cloud/api/v1/customers
```

### API Key Format

API keys follow this format:
- **Prefix:** Indicates environment and type
  - `sk_prod_` - Production keys
  - `sk_dev_` - Development keys
  - `sk_test_` - Testing keys
- **Identifier:** 4-character identifier (shown in UI)
- **Secret:** 56-character random string
- **Total Length:** 64 characters

**Example:** `sk_prod_abcd1234567890efghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV`

## Permission System

### API Key Permissions

API keys use the same permission system as users but can be more restrictive:

**Available Resources:**
- `customers` - Customer management
- `contracts` - Contract management
- `controllers` - Hardware controllers *(planned)*
- `events` - Security events *(planned)*

**Available Actions:**
- `read` - View/list resources
- `create` - Create new resources
- `update` - Modify existing resources
- `delete` - Remove resources

### Permission Examples

**Read-only access:**
```json
{
  "permissions": {
    "customers": ["read"],
    "contracts": ["read"]
  }
}
```

**Customer management:**
```json
{
  "permissions": {
    "customers": ["read", "create", "update"],
    "contracts": ["read"]
  }
}
```

**Full access:**
```json
{
  "permissions": {
    "customers": ["read", "create", "update", "delete"],
    "contracts": ["read", "create", "update", "delete"]
  }
}
```

## Rate Limiting

### Per-Key Rate Limits

Each API key has its own rate limit:
- **Default:** 1000 requests/hour
- **Configurable:** 100-10,000 requests/hour
- **Enforcement:** Per API key, not per IP

### Rate Limit Headers

When using API keys, responses include:
```http
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1735707600
X-RateLimit-Limit: 1000
```

### Rate Limit Exceeded

When rate limit is exceeded:
```json
{
  "error": "API key rate limit exceeded",
  "detail": "1000 requests per hour limit reached",
  "status": 429,
  "timestamp": 1735704000,
  "retry_after": 3600
}
```

## Security Features

### Key Security
- **SHA256 hashing** for storage
- **Prefix visibility** for identification
- **Secure generation** using cryptographic randomness
- **One-time display** during creation

### Access Control
- **Permission-based** access to resources
- **Rate limiting** per key
- **Usage tracking** and monitoring
- **Expiration dates** for temporary access

### Audit Logging
- **Creation/deletion** events logged
- **Usage statistics** tracked
- **Failed attempts** recorded
- **Permission violations** logged

## Error Responses

### Authentication Errors

**401 Unauthorized - Invalid API Key:**
```json
{
  "error": "Invalid API key",
  "status": 401,
  "timestamp": 1735704000
}
```

**401 Unauthorized - Expired API Key:**
```json
{
  "error": "API key expired",
  "detail": "Key expired on 2024-12-31T23:59:59Z",
  "status": 401,
  "timestamp": 1735704000
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "error": "Insufficient permissions",
  "detail": "API key lacks permission: customers:create",
  "status": 403,
  "timestamp": 1735704000
}
```

### Rate Limiting Errors

**429 Too Many Requests:**
```json
{
  "error": "API key rate limit exceeded",
  "detail": "1000 requests per hour limit reached",
  "status": 429,
  "timestamp": 1735704000
}
```

### Validation Errors

**400 Bad Request - Invalid Key Name:**
```json
{
  "error": "Invalid key name",
  "detail": "Key name must be 3-100 characters",
  "status": 400,
  "timestamp": 1735704000
}
```

## Best Practices

### For API Key Management
1. **Use descriptive names** that indicate purpose
2. **Set expiration dates** for temporary access
3. **Assign minimal permissions** needed for the task
4. **Regularly audit** API key usage
5. **Rotate keys periodically** (recommended: annually)

### For API Key Usage
1. **Store keys securely** (environment variables, secret managers)
2. **Never commit keys** to version control
3. **Use HTTPS only** for all API requests
4. **Monitor usage patterns** for anomalies
5. **Implement proper error handling** for rate limits

### Security Recommendations
1. **Separate keys** for different environments
2. **Limit key scope** to specific resources
3. **Monitor failed authentication** attempts
4. **Implement key rotation** procedures
5. **Use short-lived keys** for temporary access

## Testing Examples

### API Key Lifecycle Test
```bash
# 1. Create API key
KEY_RESPONSE=$(curl -s -X POST \
  https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_name":"Test Key","description":"Testing"}')

# 2. Extract API key
API_KEY=$(echo $KEY_RESPONSE | jq -r '.api_key')
KEY_ID=$(echo $KEY_RESPONSE | jq -r '.id')

# 3. Test API key usage
curl -H "X-API-Key: $API_KEY" \
  https://admin.dev.senseinfra.cloud/api/v1/customers

# 4. Check usage statistics
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys/$KEY_ID/usage

# 5. Delete test key
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/api-keys/$KEY_ID
```

### Permission Testing
```bash
# Test with limited permissions
curl -H "X-API-Key: $LIMITED_KEY" \
  https://admin.dev.senseinfra.cloud/api/v1/customers  # Should work

curl -X POST -H "X-API-Key: $LIMITED_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test"}' \
  https://admin.dev.senseinfra.cloud/api/v1/customers  # Should fail (403)
```

## Related Documentation

- [Authentication](./auth.md) - User authentication system
- [Error Handling](../03-error-handling.md) - Complete error reference
- [Security Guide](../development/security.md) - Security best practices
