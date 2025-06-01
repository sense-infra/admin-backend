# Authentication API

Complete user authentication and management system with JWT tokens and role-based access control.

## Overview

**Base Endpoints:** `/auth/*`  
**Authentication:** Mixed (public login, protected management)  
**Rate Limits:** 5 attempts/minute for login, none for authenticated endpoints

## Quick Start

```bash
# 1. Login to get JWT token
TOKEN=$(curl -s -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SenseGuard2025!"}' | jq -r '.token')

# 2. Use token for authenticated requests
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/profile
```

## Authentication Flow

### 1. User Login

**Endpoint:** `POST /auth/login`  
**Authentication:** None required  
**Rate Limit:** 5 attempts/minute per IP

**Request:**
```json
{
  "username": "admin",
  "password": "SenseGuard2025!"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@senseinfra.cloud",
    "role": {
      "id": 1,
      "name": "admin",
      "description": "Administrator"
    },
    "active": true,
    "last_login": "2025-01-01T12:00:00Z"
  },
  "expires_at": "2025-01-02T12:00:00Z",
  "force_password_change": false
}
```

**Example:**
```bash
curl -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SenseGuard2025!"
  }'
```

### 2. Get User Profile

**Endpoint:** `GET /auth/profile`  
**Authentication:** Required (JWT)

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@senseinfra.cloud",
  "first_name": "System",
  "last_name": "Administrator", 
  "role": {
    "id": 1,
    "name": "admin",
    "description": "Administrator"
  },
  "permissions": [
    {"resource": "users", "action": "read"},
    {"resource": "users", "action": "create"},
    {"resource": "customers", "action": "read"}
  ],
  "active": true,
  "created_at": "2025-01-01T00:00:00Z",
  "last_login": "2025-01-01T12:00:00Z"
}
```

### 3. Logout

**Endpoint:** `POST /auth/logout`  
**Authentication:** Required (JWT)

**Response:**
```json
{
  "message": "Successfully logged out"
}
```

## Password Management

### Change Password

**Endpoint:** `POST /auth/change-password`  
**Authentication:** Required (JWT)

**Request:**
```json
{
  "current_password": "SenseGuard2025!",
  "new_password": "NewSecurePassword123!",
  "confirm_password": "NewSecurePassword123!"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

**Example:**
```bash
curl -X POST https://admin.dev.senseinfra.cloud/api/v1/auth/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "SenseGuard2025!",
    "new_password": "NewSecurePassword123!",
    "confirm_password": "NewSecurePassword123!"
  }'
```

## User Management

### List Users

**Endpoint:** `GET /auth/users`  
**Authentication:** Required (Admin only)  
**Permissions:** `users:read`

**Response:**
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@senseinfra.cloud",
    "role": {
      "id": 1,
      "name": "admin"
    },
    "active": true,
    "last_login": "2025-01-01T12:00:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  },
  {
    "id": 2,
    "username": "viewer",
    "email": "viewer@senseinfra.cloud",
    "role": {
      "id": 2,
      "name": "viewer"
    },
    "active": true,
    "last_login": "2025-01-01T11:30:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  }
]
```

### Get User by ID

**Endpoint:** `GET /auth/users/{id}`  
**Authentication:** Required (Admin only)  
**Permissions:** `users:read`

**Parameters:**
- `id` (path) - User ID

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/users/1
```

### Create User

**Endpoint:** `POST /auth/users`  
**Authentication:** Required (Admin only)  
**Permissions:** `users:create`

**Request:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "role_id": 2,
  "active": true
}
```

**Response:**
```json
{
  "id": 3,
  "username": "newuser",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role": {
    "id": 2,
    "name": "viewer"
  },
  "active": true,
  "created_at": "2025-01-01T12:00:00Z",
  "force_password_change": true
}
```

### Update User

**Endpoint:** `PUT /auth/users/{id}`  
**Authentication:** Required (Admin only)  
**Permissions:** `users:update`

**Request:**
```json
{
  "email": "newemail@example.com",
  "first_name": "Jane",
  "active": false
}
```

### Delete User

**Endpoint:** `DELETE /auth/users/{id}`  
**Authentication:** Required (Admin only)  
**Permissions:** `users:delete`

**Response:**
```json
{
  "message": "User deleted successfully"
}
```

## Role Management

### List Roles

**Endpoint:** `GET /auth/roles`  
**Authentication:** Required (Admin only)

**Response:**
```json
[
  {
    "id": 1,
    "name": "admin",
    "description": "Administrator with full access",
    "permissions": [
      {"resource": "users", "action": "read"},
      {"resource": "users", "action": "create"},
      {"resource": "users", "action": "update"},
      {"resource": "users", "action": "delete"},
      {"resource": "customers", "action": "read"},
      {"resource": "customers", "action": "create"},
      {"resource": "customers", "action": "update"},
      {"resource": "customers", "action": "delete"},
      {"resource": "contracts", "action": "read"},
      {"resource": "contracts", "action": "create"},
      {"resource": "contracts", "action": "update"},
      {"resource": "contracts", "action": "delete"},
      {"resource": "api_keys", "action": "read"},
      {"resource": "api_keys", "action": "create"},
      {"resource": "api_keys", "action": "update"},
      {"resource": "api_keys", "action": "delete"}
    ]
  },
  {
    "id": 2,
    "name": "viewer",
    "description": "Read-only access to system data",
    "permissions": [
      {"resource": "users", "action": "read"},
      {"resource": "customers", "action": "read"},
      {"resource": "contracts", "action": "read"},
      {"resource": "api_keys", "action": "read"}
    ]
  }
]
```

## Permission System

### Permission Structure

Permissions follow the format `resource:action`:

**Resources:**
- `users` - User management
- `customers` - Customer management  
- `contracts` - Contract management
- `api_keys` - API key management
- `controllers` - Hardware controllers *(planned)*
- `events` - Security events *(planned)*

**Actions:**
- `read` - View/list resources
- `create` - Create new resources
- `update` - Modify existing resources
- `delete` - Remove resources

### Default Roles

#### Administrator Role
- **Full access** to all resources and actions
- **User management** capabilities
- **System configuration** access
- **API key management**

#### Viewer Role  
- **Read-only access** to all data
- **No modification** capabilities
- **No user management** access
- **Limited API key** viewing

## Error Responses

### Authentication Errors

**401 Unauthorized - Invalid Credentials:**
```json
{
  "error": "Invalid credentials",
  "status": 401,
  "timestamp": 1735704000
}
```

**401 Unauthorized - Missing Token:**
```json
{
  "error": "Authentication required",
  "status": 401,
  "timestamp": 1735704000
}
```

**403 Forbidden - Insufficient Permissions:**
```json
{
  "error": "Insufficient permissions",
  "detail": "Required permission: users:create",
  "status": 403,
  "timestamp": 1735704000
}
```

### Rate Limiting Errors

**429 Too Many Requests:**
```json
{
  "error": "Rate limit exceeded",
  "detail": "Too many login attempts",
  "status": 429,
  "timestamp": 1735704000
}
```

### Validation Errors

**400 Bad Request - Missing Fields:**
```json
{
  "error": "Missing required field",
  "detail": "username is required",
  "status": 400,
  "timestamp": 1735704000
}
```

**409 Conflict - Duplicate User:**
```json
{
  "error": "User already exists",
  "detail": "username must be unique",
  "status": 409,
  "timestamp": 1735704000
}
```

## Security Features

### Password Security
- **Bcrypt hashing** with cost factor 12
- **Minimum complexity** requirements
- **Force password change** for new users
- **Account locking** after failed attempts

### JWT Token Details
- **Algorithm:** HMAC SHA256
- **Expiration:** 24 hours (configurable)
- **Claims:** User ID, username, role, permissions

### Default Credentials

⚠️ **Change these immediately in production:**

- **Admin:** `admin` / `SenseGuard2025!`
- **Viewer:** `viewer` / `Viewer2025!`

## Testing Examples

```bash
# Test authentication flow
TOKEN=$(curl -s -X POST \
  https://admin.dev.senseinfra.cloud/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SenseGuard2025!"}' | jq -r '.token')

# Test authenticated endpoint
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/profile

# Test user management
curl -H "Authorization: Bearer $TOKEN" \
  https://admin.dev.senseinfra.cloud/api/v1/auth/users
```

## Related Documentation

- [API Keys](./api-keys.md) - Programmatic access management
- [Error Handling](../03-error-handling.md) - Complete error reference
- [Security Guide](../development/security.md) - Security best practices
