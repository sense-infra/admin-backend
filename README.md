
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
  "email": "test@cust.com",
  "password": "Aa123456#"
}
```

### Response `200 OK`
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b21lcl9pZCI6NSwiZW1haWwiOiJ0ZXN0QGN1c3QuY29tIiwibmFtZSI6ImN1c3QxMSIsInNlc3Npb25faWQiOiJ0M2JVR0ZYRUlYdWFDZmxwYXV2bUstZ3BMUkNUR1c1UTA5VklGdmV3eEcwPSIsImNvbnRyYWN0X2lkcyI6bnVsbCwiZXhwIjoxNzUyNjYzODM3LCJpYXQiOjE3NTI1Nzc0MzcsImp0aSI6InQzYlVHRlhFSVh1YUNmbHBhdXZtSy1ncExSQ1RHVzVRMDlWSUZ2ZXd4RzA9In0.K2uLP0WyES0X3Qcf8R6kNuFVVw1e_grYprvMB2nDL-4",
  "expires_at": "2025-07-16T04:03:57.848612-07:00"
}
```

### cURL Example
```bash
curl -X POST http://localhost:8080/client/auth/login \
  -H "Content-Type: application/json" \
  -d '{
        "email": "test@cust.com",
        "password": "Aa123456#"
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
curl -X POST http://localhost:8080/client/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## POST `/client/auth/change-password`

Allows a logged-in customer to change their password.

### Request Body
```json
{
  "old_password": "Aa123456#",
  "new_password": "Bb7891011@"
}
```

### Headers
- `Authorization: Bearer <JWT>`

### Response `204 No Content`

### cURL Example
```bash
curl -X POST http://localhost:8080/client/auth/change-password \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
        "old_password": "Aa123456#",
        "new_password": "Bb7891011@"
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
  "customer_id": 5,
  "name_on_contract": "cust11",
  "email": "test@cust.com",
  "phone_number": "1234567890",
  "address": "123 Main Str",
  "active": true,
  "created_at": "2025-06-15T13:28:35Z"
}
```

### cURL Example
```bash
curl http://localhost:8080/client/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

