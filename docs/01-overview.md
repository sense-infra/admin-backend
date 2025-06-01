# API Overview

## Base URL & Versioning

**Base URL:** `https://admin.dev.senseinfra.cloud/api/v1/`

All API endpoints are relative to this base URL. The API uses semantic versioning in the URL path.

**Examples:**
```
https://admin.dev.senseinfra.cloud/api/v1/health
https://admin.dev.senseinfra.cloud/api/v1/auth/login
https://admin.dev.senseinfra.cloud/api/v1/customers
```

## Authentication

The API supports two authentication methods:

### 1. JWT Bearer Token (Primary)
Used for web interface and user sessions.

**Header:**
```http
Authorization: Bearer <jwt_token>
```

**Example:**
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  https://admin.dev.senseinfra.cloud/api/v1/auth/profile
```

### 2. API Key (Programmatic Access)
Used for service-to-service communication and automation.

**Header:**
```http
X-API-Key: <api_key>
```

**Alternative:**
```http
Authorization: Bearer <api_key>
```

**Example:**
```bash
curl -H "X-API-Key: sk_prod_abc123..." \
  https://admin.dev.senseinfra.cloud/api/v1/customers
```

## Rate Limiting

Rate limiting is applied to prevent abuse and DDoS attacks:

- **Health endpoints:** 10 requests/minute per IP
- **Login endpoints:** 5 attempts/minute per IP  
- **Authenticated endpoints:** No rate limiting (protected by authentication)

### Rate Limit Headers

When rate limits are applied, the API returns these headers:

```http
X-RateLimit-Limit: 10
X-RateLimit-Window: 60s
Retry-After: 60
```

### Rate Limit Response

When rate limits are exceeded:

```json
{
  "error": "Rate limit exceeded",
  "detail": "Too many requests from your IP address",
  "status": 429,
  "timestamp": 1735704000
}
```

## Response Format

### Success Response Structure

All successful API responses follow this format:

```json
{
  "data": { ... },
  "status": 200,
  "timestamp": 1735704000
}
```

**Note:** For simplicity, most documentation examples show only the `data` content.

### Pagination

List endpoints support pagination with these parameters:

- `limit` - Number of results (default: 50, max: 100)
- `offset` - Starting position (default: 0)

**Example:**
```bash
curl "https://admin.dev.senseinfra.cloud/api/v1/customers?limit=10&offset=20"
```

**Response:**
```json
{
  "customers": [...],
  "total": 150,
  "limit": 10,
  "offset": 20,
  "has_more": true
}
```

## Content Types

### Request Content-Type
All POST and PUT requests must use:
```http
Content-Type: application/json
```

### Response Content-Type
All responses return:
```http
Content-Type: application/json
```

### Character Encoding
All content uses UTF-8 encoding.

## Date and Time Format

All timestamps use ISO 8601 format (RFC 3339) in UTC:

```json
{
  "created_at": "2025-01-01T12:00:00Z",
  "updated_at": "2025-01-01T12:30:45Z"
}
```

## Field Naming Convention

The API uses `snake_case` for all field names:

```json
{
  "customer_id": 1,
  "name_on_contract": "John Smith",
  "phone_number": "+1-555-0123",
  "created_at": "2025-01-01T12:00:00Z"
}
```

## Request Limits

- **Maximum request size:** 10MB
- **Maximum response size:** 50MB  
- **Request timeout:** 30 seconds
- **Maximum pagination limit:** 1000 records per request

## CORS Support

The API supports Cross-Origin Resource Sharing (CORS) with these headers:

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key
Access-Control-Max-Age: 3600
```

## Security Headers

The API includes security-related headers in responses:

```http
X-Health-Cache: hit|miss
X-Health-Type: cached|quick|detailed
X-RateLimit-Limit: 10
X-RateLimit-Window: 60s
```

## API Versioning Strategy

- **Current Version:** v1.0.0
- **URL Versioning:** Version included in URL path (`/api/v1/`)
- **Backward Compatibility:** Maintained within major versions
- **Deprecation:** 6-month notice for breaking changes

## Environment Information

### Development
- **Base URL:** `https://admin.dev.senseinfra.cloud/api/v1/`
- **Rate Limiting:** Enabled
- **HTTPS:** Required

### Production  
- **Base URL:** `https://admin.senseinfra.cloud/api/v1/`
- **Rate Limiting:** Strict enforcement
- **HTTPS:** Required with HSTS

## Next Steps

- [Getting Started](./02-getting-started.md) - Authentication flow and first requests
- [Error Handling](./03-error-handling.md) - Understanding API errors
- [API Reference](./reference/endpoints.md) - Complete endpoint documentation
