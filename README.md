# Sense Security Client API Documentation

This section documents the **Client Authentication & Account API** for the Sense Security Platform.

## 🔐 Authentication Overview

Customers authenticate using email and password. All authenticated requests require a `Bearer` JWT in the `Authorization` header.

Base path: `/client`

---

## POST `/client/auth/login`

Authenticate a customer and receive a JWT token.

### Request Body
```json
{
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

### Response `200 OK`
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-07-15T23:59:59Z"
}
```

### cURL Example
```bash
curl -X POST https://yourdomain.com/client/auth/login \
  -H "Content-Type: application/json" \
  -d '{
        "email": "john@example.com",
        "password": "SecurePass123"
      }'
```

---

## POST `/client/auth/logout`

Logs the customer out and invalidates the session token.

### Headers
- `Authorization: Bearer <JWT>`

### Response `200 OK`
No content.

### cURL Example
```bash
curl -X POST https://yourdomain.com/client/auth/logout \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## POST `/client/auth/change-password`

Allows a logged-in customer to change their password.

### Request Body
```json
{
  "old_password": "SecurePass123",
  "new_password": "EvenMoreSecure456"
}
```

### Headers
- `Authorization: Bearer <JWT>`

### Response `204 No Content`

### cURL Example
```bash
curl -X POST https://yourdomain.com/client/auth/change-password \
  -H "Authorization: Bearer eyJhbGciOi..." \
  -H "Content-Type: application/json" \
  -d '{
        "old_password": "SecurePass123",
        "new_password": "EvenMoreSecure456"
      }'
```

---

## GET `/client/profile`

Returns the authenticated customer’s profile (read-only).

### Headers
- `Authorization: Bearer <JWT>`

### Response `200 OK`
```json
{
  "customer_id": 42,
  "name_on_contract": "John Doe",
  "email": "john@example.com",
  "phone_number": "555-1234",
  "address": "123 Main St",
  "active": true,
  "created_at": "2025-06-01T10:30:00Z"
}
```

### cURL Example
```bash
curl https://yourdomain.com/client/profile \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## GET `/client/dashboard`

Returns a summary dashboard for the customer.

### Headers
- `Authorization: Bearer <JWT>`

### Response `200 OK`
```json
{
  "contract_count": 2,
  "equipment_count": 5,
  "active_alerts": 0
}
```

### cURL Example
```bash
curl https://yourdomain.com/client/dashboard \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## GET `/client/contracts`

Lists all contracts for the authenticated customer.

### Headers
- `Authorization: Bearer <JWT>`

### Response `200 OK`
```json
[
  {
    "contract_id": 1001,
    "name": "Main Office Monitoring",
    "status": "active"
  },
  {
    "contract_id": 1002,
    "name": "Warehouse Coverage",
    "status": "inactive"
  }
]
```

### cURL Example
```bash
curl https://yourdomain.com/client/contracts \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## GET `/client/contracts/{id}`

Fetch details for a specific contract.

### Path Parameter
- `id` – Contract ID (integer)

### Headers
- `Authorization: Bearer <JWT>`

### Response `200 OK`
```json
{
  "contract_id": 1001,
  "name": "Main Office Monitoring",
  "status": "active",
  "start_date": "2024-01-01",
  "end_date": "2026-01-01"
}
```

### cURL Example
```bash
curl https://yourdomain.com/client/contracts/1001 \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## GET `/client/contracts/{id}/service-tier`

Returns the service tier assigned to the specified contract.

### Path Parameter
- `id` – Contract ID (integer)

### Headers
- `Authorization: Bearer <JWT>`

### Response `200 OK`
```json
{
  "tier": "Premium",
  "features": [
    "24/7 Monitoring",
    "Unlimited Cameras",
    "Remote Access Support"
  ]
}
```

### cURL Example
```bash
curl https://yourdomain.com/client/contracts/1001/service-tier \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## 🔐 Authentication Notes

- All customer endpoints require a valid JWT via `Authorization: Bearer <token>`
- Tokens expire based on server policy (e.g., 1–24 hours)
- On logout, sessions are deleted and token is no longer valid
- Passwords are securely stored using bcrypt
- Customers must change password on first login if `force_password_change` is true

