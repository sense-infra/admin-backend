# Health Check API

The Health Check API provides system monitoring with built-in DDoS protection through intelligent caching.

## Overview

**Endpoint:** `GET /health`  
**Authentication:** None required  
**Rate Limit:** 10 requests/minute per IP

## Features

- ✅ **Cached responses** (30-second TTL) prevent database overload
- ✅ **Three health check modes** for different use cases
- ✅ **DDoS protection** through rate limiting and caching
- ✅ **Timeout protection** prevents hanging on slow database
- ✅ **Informative headers** for debugging and monitoring

## Health Check Modes

### 1. Cached Health Check (Default)

Returns cached health status to prevent database DDoS attacks.

**Request:**
```bash
curl https://admin.dev.senseinfra.cloud/api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "SenseGuard Security Platform",
  "version": "1.0.0",
  "type": "cached",
  "database": "connected",
  "timestamp": 1735704000,
  "cache_ttl": 30
}
```

**Response Headers:**
```http
X-Health-Cache: hit
X-Health-Type: cached
```

### 2. Quick Health Check

Skips all database checks for instant response - perfect for load balancers.

**Request:**
```bash
curl "https://admin.dev.senseinfra.cloud/api/v1/health?quick=true"
```

**Response:**
```json
{
  "status": "healthy",
  "service": "SenseGuard Security Platform",
  "version": "1.0.0",
  "type": "quick",
  "database": "not_checked",
  "timestamp": 1735704000
}
```

**Response Headers:**
```http
X-Health-Type: quick
```

### 3. Detailed Health Check

Performs comprehensive database tests - should only be used by authenticated admin users.

**Request:**
```bash
curl "https://admin.dev.senseinfra.cloud/api/v1/health?detailed=true"
```

**Response:**
```json
{
  "status": "healthy",
  "service": "SenseGuard Security Platform",
  "version": "1.0.0",
  "type": "detailed",
  "database": {
    "status": "healthy",
    "query_test": "passed",
    "response_time": 1.2
  },
  "checks": {
    "database": {
      "status": "healthy",
      "query_test": "passed",
      "response_time": 1.2
    }
  },
  "timestamp": 1735704000
}
```

**Response Headers:**
```http
X-Health-Type: detailed
```

## Status Values

| Status | Description | HTTP Code |
|--------|-------------|-----------|
| `healthy` | All systems operational | 200 |
| `degraded` | Database connected but queries failing | 200 |
| `unhealthy` | Database disconnected or timeout | 503 |

## Use Cases

### Load Balancer Health Checks
Use quick mode for fastest response:
```bash
curl "https://admin.dev.senseinfra.cloud/api/v1/health?quick=true"
```

### Monitoring Dashboard
Use cached mode for regular monitoring:
```bash
curl https://admin.dev.senseinfra.cloud/api/v1/health
```

### Administrative Troubleshooting
Use detailed mode for comprehensive diagnostics:
```bash
curl "https://admin.dev.senseinfra.cloud/api/v1/health?detailed=true"
```

## Error Responses

### Service Unavailable (503)

When the database is unreachable:

```json
{
  "status": "unhealthy",
  "service": "SenseGuard Security Platform", 
  "version": "1.0.0",
  "type": "cached",
  "database": "disconnected",
  "error": "Database connection failed",
  "timestamp": 1735704000
}
```

### Rate Limit Exceeded (429)

When too many requests are made:

```json
{
  "error": "Rate limit exceeded",
  "detail": "Too many health check requests",
  "status": 429,
  "timestamp": 1735704000
}
```

**Headers:**
```http
X-RateLimit-Limit: 10
X-RateLimit-Window: 60s
Retry-After: 60
```

## Caching Behavior

### Cache Duration
- **TTL:** 30 seconds
- **Cache Key:** Global (shared across all requests)
- **Cache Invalidation:** Time-based only

### Cache Headers

| Header | Values | Description |
|--------|--------|-------------|
| `X-Health-Cache` | `hit`, `miss` | Cache status |
| `X-Health-Type` | `cached`, `quick`, `detailed` | Check type performed |

### Cache Miss Conditions
- First request after server start
- Cache expired (>30 seconds since last check)
- Database status changed

## Security Features

### DDoS Protection
1. **Rate Limiting:** 10 requests/minute per IP
2. **Response Caching:** 30-second cache prevents database overload
3. **Timeout Protection:** 5-second database timeout prevents hanging
4. **Quick Mode:** No database queries for load balancer checks

### Monitoring Integration
- **Prometheus:** Metrics available at `/metrics` (if enabled)
- **Health Status:** Machine-readable status for monitoring tools
- **Response Time:** Database query performance metrics

## Testing Examples

### Basic Functionality Test
```bash
# Test default health check
curl -i https://admin.dev.senseinfra.cloud/api/v1/health

# Verify response headers
curl -I https://admin.dev.senseinfra.cloud/api/v1/health
```

### Rate Limiting Test
```bash
# Test rate limiting (should trigger after 10 requests)
for i in {1..15}; do
  echo "Request $i:"
  curl -w "HTTP %{http_code}\n" https://admin.dev.senseinfra.cloud/api/v1/health
  sleep 1
done
```

### Cache Behavior Test
```bash
# First request (cache miss)
curl -H "X-Debug: true" https://admin.dev.senseinfra.cloud/api/v1/health

# Second request (cache hit)
curl -H "X-Debug: true" https://admin.dev.senseinfra.cloud/api/v1/health

# Wait 31 seconds and request again (cache miss)
sleep 31
curl -H "X-Debug: true" https://admin.dev.senseinfra.cloud/api/v1/health
```

## Performance Characteristics

### Response Times
- **Quick Mode:** <10ms (no database queries)
- **Cached Mode:** <10ms (cache hit), <100ms (cache miss)
- **Detailed Mode:** 10-50ms (includes database query tests)

### Resource Usage
- **Memory:** Minimal cache storage (<1KB)
- **Database Connections:** 0 (quick), 1 (cached/detailed)
- **CPU:** Negligible impact

## Troubleshooting

### Health Check Failing

1. **Check database connectivity:**
   ```bash
   curl "https://admin.dev.senseinfra.cloud/api/v1/health?detailed=true"
   ```

2. **Verify service status:**
   ```bash
   curl -i https://admin.dev.senseinfra.cloud/api/v1/health
   ```

3. **Check rate limiting:**
   ```bash
   curl -I https://admin.dev.senseinfra.cloud/api/v1/health
   # Look for X-RateLimit-* headers
   ```

### Common Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| Rate limited | HTTP 429 | Wait 1 minute or use different IP |
| Database down | `status: "unhealthy"` | Check database connection |
| Slow response | Timeout errors | Use quick mode for load balancers |
| Cache issues | Inconsistent responses | Check cache headers |

## Related Documentation

- [API Overview](../01-overview.md) - Authentication and rate limiting
- [Error Handling](../03-error-handling.md) - Error response format
- [Diagnostics API](./diagnostics.md) - Advanced system monitoring
