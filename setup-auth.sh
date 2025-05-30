#!/bin/bash

# SenseGuard Authentication Setup Script
# This script sets up the authentication system with default users

echo "🔐 Setting up SenseGuard Authentication System..."

# Function to detect and use available database client
detect_db_client() {
    # Check if MYSQL_CLIENT environment variable is set
    if [ -n "$MYSQL_CLIENT" ] && [ -x "$MYSQL_CLIENT" ]; then
        echo "✅ Using specified MySQL client: $MYSQL_CLIENT"
        return 0
    fi
    
    # Check standard PATH
    if command -v mariadb &> /dev/null; then
        echo "✅ Found MariaDB client in PATH"
        MYSQL_CLIENT="mariadb"
        return 0
    elif command -v mysql &> /dev/null; then
        echo "✅ Found MySQL client in PATH"
        MYSQL_CLIENT="mysql"
        return 0
    fi
    
    # Check common Homebrew paths for macOS
    local homebrew_paths=(
        "/opt/homebrew/bin/mysql"           # Apple Silicon Macs (M1/M2)
        "/usr/local/bin/mysql"              # Intel Macs
        "/opt/homebrew/opt/mysql-client/bin/mysql"  # MySQL client specific (Apple Silicon)
        "/usr/local/opt/mysql-client/bin/mysql"     # MySQL client specific (Intel)
        "/opt/homebrew/opt/mysql/bin/mysql"         # Full MySQL (Apple Silicon)
        "/usr/local/opt/mysql/bin/mysql"            # Full MySQL (Intel)
        "/opt/homebrew/bin/mariadb"         # MariaDB on Apple Silicon
        "/usr/local/bin/mariadb"            # MariaDB on Intel
    )
    
    for path in "${homebrew_paths[@]}"; do
        if [ -x "$path" ]; then
            echo "✅ Found MySQL/MariaDB client at: $path"
            MYSQL_CLIENT="$path"
            return 0
        fi
    done
    
    echo "❌ No database client found in PATH or common locations"
    echo ""
    echo "🔍 Homebrew MySQL/MariaDB installation detected?"
    if command -v brew &> /dev/null; then
        echo "   Checking Homebrew installations..."
        if brew list mysql-client &> /dev/null; then
            echo "   • mysql-client is installed via Homebrew"
        fi
        if brew list mysql &> /dev/null; then
            echo "   • mysql is installed via Homebrew"
        fi
        if brew list mariadb &> /dev/null; then
            echo "   • mariadb is installed via Homebrew"
        fi
        echo ""
        echo "🔧 Try running the path fix script first:"
        echo "   chmod +x fix-mysql-path.sh"
        echo "   ./fix-mysql-path.sh"
        echo ""
    fi
    
    echo "📥 Install options:"
    echo "  • MariaDB client: brew install mariadb"
    echo "  • MySQL client: brew install mysql-client"
    echo "  • Full MySQL: brew install mysql"
    echo "  • On Linux: sudo apt-get install mariadb-client"
    echo ""
    echo "📋 Alternative: Apply the schema manually using your preferred database tool"
    return 1
}

# Function to execute SQL with available client
execute_sql() {
    local sql_file="$1"
    local sql_command="$2"
    
    if [ -n "$sql_file" ]; then
        "$MYSQL_CLIENT" -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < "$sql_file"
    else
        "$MYSQL_CLIENT" -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASSWORD" -e "$sql_command" "$DB_NAME"
    fi
}

# Check for database client
if ! detect_db_client; then
    echo ""
    echo "🔧 Manual Setup Instructions:"
    echo "1. Connect to your MariaDB server at: $DB_HOST:$DB_PORT"
    echo "2. Use database: $DB_NAME"
    echo "3. Run the SQL file: sql/auth_schema.sql"
    echo "4. Install Go dependencies and build the application"
    echo ""
    echo "To continue with manual setup, run:"
    echo "  go mod tidy"
    echo "  go get github.com/golang-jwt/jwt/v5"
    echo "  go get golang.org/x/crypto/bcrypt"
    echo "  go get github.com/go-playground/validator/v10"
    echo "  go build -o senseguard-server ."
    exit 1
fi

# Load environment variables
if [ -f .env ]; then
    source .env
    echo "✅ Loaded environment variables from .env"
else
    echo "⚠️  No .env file found, using defaults"
    DB_HOST=${DB_HOST:-dev-mariadb-ms.dev}
    DB_PORT=${DB_PORT:-3306}
    DB_USER=${DB_USER:-admin}
    DB_PASSWORD=${DB_PASSWORD:-changeme}
    DB_NAME=${DB_NAME:-dev}
fi

# Test database connection
echo "🔍 Testing database connection..."
if execute_sql "" "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Database connection successful"
else
    echo "❌ Cannot connect to database. Please check your credentials and ensure MariaDB is running."
    echo "   Host: $DB_HOST:$DB_PORT"
    echo "   Database: $DB_NAME"
    echo "   Username: $DB_USER"
    echo ""
    echo "🔧 Troubleshooting steps:"
    echo "1. Verify MariaDB server is running"
    echo "2. Check if the database '$DB_NAME' exists"
    echo "3. Verify user '$DB_USER' has access to the database"
    echo "4. Check network connectivity to $DB_HOST"
    echo "5. Verify credentials in .env file"
    echo ""
    echo "Test connection manually:"
    echo "  $MYSQL_CLIENT -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASSWORD $DB_NAME"
    exit 1
fi

# Check if auth schema file exists
if [ ! -f "sql/auth_schema.sql" ]; then
    echo "❌ Authentication schema file not found: sql/auth_schema.sql"
    echo "   Please ensure the file exists in the sql/ directory"
    exit 1
fi

# Apply authentication schema
echo "📊 Applying authentication schema..."
if execute_sql "sql/auth_schema.sql"; then
    echo "✅ Authentication schema applied successfully"
else
    echo "❌ Failed to apply authentication schema"
    echo "   Check if tables already exist or if there are permission issues"
    echo ""
    echo "To apply manually, run:"
    echo "  $MYSQL_CLIENT -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASSWORD $DB_NAME < sql/auth_schema.sql"
    exit 1
fi

# Generate JWT secret if not set
if [ -z "$JWT_SECRET" ] || [ "$JWT_SECRET" = "your_super_secret_jwt_key_here_change_in_production" ]; then
    echo "🔑 Generating JWT secret..."
    
    # Try different methods to generate random string
    if command -v openssl &> /dev/null; then
        JWT_SECRET=$(openssl rand -base64 32)
    elif command -v head &> /dev/null && [ -f /dev/urandom ]; then
        JWT_SECRET=$(head -c 32 /dev/urandom | base64)
    else
        # Fallback: use current timestamp and hostname
        JWT_SECRET=$(echo "$(date +%s)-$(hostname)-$(whoami)" | base64)
        echo "⚠️  Using fallback method for JWT secret generation"
    fi
    
    # Update .env file
    if [ -f .env ]; then
        if grep -q "JWT_SECRET=" .env; then
            sed -i.bak "s/JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
        else
            echo "JWT_SECRET=$JWT_SECRET" >> .env
        fi
    else
        echo "JWT_SECRET=$JWT_SECRET" > .env
    fi
    echo "✅ JWT secret generated and saved to .env"
fi

# Install Go dependencies
echo "📦 Installing Go dependencies..."
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed or not in PATH"
    echo "   Please install Go from https://golang.org/dl/"
    exit 1
fi

go mod tidy
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt
go get github.com/go-playground/validator/v10

if [ $? -eq 0 ]; then
    echo "✅ Go dependencies installed successfully"
else
    echo "❌ Failed to install Go dependencies"
    echo "   Check your internet connection and Go installation"
    exit 1
fi

# Create web directory and check for admin interface
echo "🌐 Setting up web interface..."
mkdir -p web
if [ ! -f web/admin.html ]; then
    echo "⚠️  admin.html not found in web/ directory"
    echo "   Please ensure you have the admin.html file in the web/ directory"
    echo "   You can still use the API endpoints without the web interface"
fi

# Build the application
echo "🔨 Building the application..."
go build -o senseguard-server .

if [ $? -eq 0 ]; then
    echo "✅ Application built successfully"
    # Make the binary executable
    chmod +x senseguard-server
else
    echo "❌ Failed to build application"
    echo "   Check for compilation errors in your Go code"
    exit 1
fi

# Display setup information
echo ""
echo "🎉 SenseGuard Authentication Setup Complete!"
echo ""
echo "📋 Setup Summary:"
echo "   • Authentication schema applied to MariaDB database"
echo "   • Default admin and viewer users created"
echo "   • JWT secret generated"
echo "   • Go dependencies installed"
echo "   • Application built successfully"
echo ""
echo "🔑 Default Credentials:"
echo "   Admin User:"
echo "     Username: admin"
echo "     Password: SenseGuard2025!"
echo "     Email: admin@senseguard.local"
echo ""
echo "   Viewer User:"
echo "     Username: viewer"
echo "     Password: Viewer2025!"
echo "     Email: viewer@senseguard.local"
echo ""
echo "🚀 To start the server:"
echo "   ./senseguard-server"
echo ""
echo "🌐 Access the admin interface at:"
echo "   http://localhost:${SERVER_PORT:-8080}"
echo ""
echo "📡 API Health Check:"
echo "   curl http://localhost:${SERVER_PORT:-8080}/api/v1/health"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "   1. Change all default passwords immediately after first login"
echo "   2. The system forces password change on first login"
echo "   3. Review and update the JWT_SECRET in production"
echo "   4. Configure proper firewall rules"
echo "   5. Use HTTPS in production environments"
echo ""
echo "📚 API Documentation:"
echo "   Health Check: GET /api/v1/health"
echo "   Login: POST /api/v1/auth/login"
echo "   API endpoints require authentication via Bearer token or X-API-Key header"
echo ""
echo "🔧 Database Connection:"
echo "   Host: $DB_HOST:$DB_PORT"
echo "   Database: $DB_NAME"
echo "   User: $DB_USER"
echo ""

echo "✅ Setup script completed successfully!"
echo "   You can now run: ./senseguard-server"
