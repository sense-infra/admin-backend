#!/bin/bash

# Debug API Keys Response to see the exact JSON structure

echo "=== Getting Auth Token ==="
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SenseGuard2025!"}')

echo "Login Response: $TOKEN_RESPONSE"

# Extract token (manually copy the token value from above)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZV9pZCI6MSwic2Vzc2lvbl9pZCI6Imo4dXpZUFlZVmhqc3dPMm5xR3ZFQVd6Rjk5d3Jzc090Y2dpcV9pZHNTdGc9IiwiZXhwIjoxNzQ4NzE5OTAyLCJpYXQiOjE3NDg2MzM1MDIsImp0aSI6Imo4dXpZUFlZVmhqc3dPMm5xR3ZFQVd6Rjk5d3Jzc090Y2dpcV9pZHNTdGc9In0.vgeOBW0RsgQQAl-zXZlbouPnRNbpZq4NlO597xgtVCI"

echo ""
echo "=== Raw API Keys Response (to debug structure) ==="
curl -s -X GET http://localhost:8080/api/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" | jq '.[0]' || curl -s -X GET http://localhost:8080/api/auth/api-keys \
  -H "Authorization: Bearer $TOKEN"

echo ""
echo "=== Creating a test API key ==="
curl -s -X POST http://localhost:8080/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "key_name": "Debug Test Key",
    "description": "Testing creator field",
    "permissions": {
      "customers": ["read"]
    }
  }' | jq '.'

echo ""
echo "=== API Keys after creation ==="
curl -s -X GET http://localhost:8080/api/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" | jq '.'
