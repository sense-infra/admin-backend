#!/bin/bash

# Monitor database connections
echo "Monitoring database connections..."
echo "================================"

API_KEY=$(cat .api-key)

# Function to check connections
check_connections() {
    echo -n "$(date '+%Y-%m-%d %H:%M:%S') - "
    
    # Make API call and capture full response
    RESPONSE=$(curl -s -w "\n%{http_code}" -H "X-API-Key: $API_KEY" "http://localhost:8080/api/customers?limit=1&offset=0" 2>/dev/null)
    
    # Extract HTTP code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    
    # Extract body (all except last line)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ "$HTTP_CODE" = "200" ]; then
        # Try to parse JSON
        if command -v jq &> /dev/null; then
            COUNT=$(echo "$BODY" | jq '. | length' 2>/dev/null || echo "0")
            if [ "$COUNT" = "0" ]; then
                echo "WARNING - HTTP $HTTP_CODE - Empty result! Body: $BODY"
            else
                FIRST_ID=$(echo "$BODY" | jq '.[0].customer_id' 2>/dev/null || echo "?")
                echo "OK - HTTP $HTTP_CODE - Records: $COUNT - First ID: $FIRST_ID"
            fi
        else
            echo "OK - HTTP $HTTP_CODE - Body: ${BODY:0:50}..."
        fi
    else
        echo "ERROR - HTTP $HTTP_CODE - Body: $BODY"
    fi
}

# Check every 2 seconds
while true; do
    check_connections
    sleep 2
done
