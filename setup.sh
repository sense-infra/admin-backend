#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up Sense Security API...${NC}"

# Create directory structure
echo "Creating directory structure..."
mkdir -p config db handlers middleware models

# Generate API key
API_KEY=$(openssl rand -hex 32)
echo $API_KEY > .api-key
echo -e "${YELLOW}Generated API Key: $API_KEY${NC}"
echo -e "${YELLOW}(saved to .api-key)${NC}"

# Create .env file with your MySQL details
cat > .env << ENVFILE
# Server Configuration
SERVER_PORT=:8080

# Database Configuration
DB_HOST=dev-mariadb-ms.dev
DB_PORT=3306
DB_USER=admin
DB_PASSWORD=changeme
DB_NAME=dev
DB_SSLMODE=false

# API Keys
API_KEYS=$API_KEY
ENVFILE

echo -e "${GREEN}Created .env file with your MySQL configuration${NC}"

# Create source script
cat > source-env.sh << 'SRCFILE'
#!/bin/bash
export $(grep -v '^#' .env | xargs)
echo "Environment loaded from .env"
echo "Database: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo "API Key: ${API_KEYS:0:8}..."
SRCFILE
chmod +x source-env.sh

# Create .gitignore
cat > .gitignore << GITFILE
.env
.api-key
*.exe
*.dll
*.so
*.dylib
*.test
*.out
.idea/
.vscode/
*.swp
*.swo
*~
vendor/
bin/
dist/
GITFILE

# Create go.mod
cat > go.mod << 'GOMOD'
module github.com/sense-security/api

go 1.21

require (
    github.com/go-sql-driver/mysql v1.7.1
    github.com/gorilla/mux v1.8.1
)
GOMOD

echo -e "${GREEN}Project structure created!${NC}"
echo ""
echo -e "${YELLOW}Your configuration:${NC}"
echo "  Database: admin@dev-mariadb-ms.dev:3306/dev"
echo "  API Key: $API_KEY"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Copy the code files from the artifacts"
echo "2. Run: source ./source-env.sh"
echo "3. Run: go mod download"
echo "4. Run: go run main.go"
