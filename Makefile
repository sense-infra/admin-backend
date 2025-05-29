.PHONY: help setup run build test clean db-test api-test

# Load API key if exists
API_KEY := $(shell cat .api-key 2>/dev/null || echo "no-key-found")

help:
	@echo "Sense Security API - Available commands:"
	@echo "  make setup      - Run initial setup"
	@echo "  make run        - Run the API server"
	@echo "  make build      - Build the binary"
	@echo "  make test       - Run all tests"
	@echo "  make db-test    - Test database connection"
	@echo "  make api-test   - Test API endpoints"
	@echo "  make clean      - Clean build artifacts"

setup:
	@./setup.sh
	@./create-stubs.sh
	@echo "Setup complete! Now copy the code from artifacts to the respective files."

run:
	@echo "Starting API server..."
	@source ./source-env.sh && go run main.go

build:
	@echo "Building sense-api..."
	@go build -o bin/sense-api .
	@echo "Binary created at bin/sense-api"

db-test:
	@echo "Testing database connection..."
	@mysql -h dev-mariadb-ms.dev -u admin -pchangeme -e "SELECT 'Database connection successful!' as Status;"

api-test:
	@echo "Testing API endpoints..."
	@echo ""
	@echo "Health check:"
	@curl -s http://localhost:8080/health | jq . || echo "API not running?"
	@echo ""
	@echo "Ready check:"
	@curl -s http://localhost:8080/ready | jq . || echo "API not running?"
	@echo ""
	@echo "Customers endpoint (with auth):"
	@curl -s -H "X-API-Key: $(API_KEY)" http://localhost:8080/api/customers | jq . || echo "API not running?"

test-create-customer:
	@echo "Creating test customer..."
	@curl -s -X POST http://localhost:8080/api/customers \
		-H "X-API-Key: $(API_KEY)" \
		-H "Content-Type: application/json" \
		-d '{"name_on_contract":"Test User","address":"123 Test St","unique_id":"TEST-$(shell date +%s)","email":"test@example.com","phone_number":"+1234567890"}' \
		| jq .

test-create-contract:
	@echo "Creating test contract..."
	@curl -s -X POST http://localhost:8080/api/contracts \
		-H "X-API-Key: $(API_KEY)" \
		-H "Content-Type: application/json" \
		-d '{"service_address":"456 Service Ave","notification_email":"notify@example.com","start_date":"2024-01-01T00:00:00Z","end_date":"2025-01-01T00:00:00Z"}' \
		| jq .

clean:
	@rm -rf bin/
	@rm -f sense-api
	@echo "Cleaned build artifacts"

download-deps:
	@echo "Downloading Go dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies downloaded!"

# Development helpers
dev: setup download-deps
	@echo "Ready for development!"
	@echo "Your API Key: $(API_KEY)"
	@echo ""
	@echo "Next: make run"
