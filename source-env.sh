#!/bin/bash
export $(grep -v '^#' .env | xargs)
echo "Environment loaded from .env"
echo "Database: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo "API Key: ${API_KEYS:0:8}..."
