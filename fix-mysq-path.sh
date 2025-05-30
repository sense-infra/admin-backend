#!/bin/bash

# Fix MySQL client PATH for Homebrew installations
echo "🔍 Searching for MySQL client installed via Homebrew..."

# Common Homebrew MySQL paths
HOMEBREW_PATHS=(
    "/opt/homebrew/bin"           # Apple Silicon Macs (M1/M2)
    "/usr/local/bin"              # Intel Macs
    "/opt/homebrew/opt/mysql-client/bin"  # MySQL client specific path (Apple Silicon)
    "/usr/local/opt/mysql-client/bin"     # MySQL client specific path (Intel)
    "/opt/homebrew/opt/mysql/bin"         # Full MySQL (Apple Silicon)
    "/usr/local/opt/mysql/bin"            # Full MySQL (Intel)
)

MYSQL_FOUND=""
MYSQL_PATH=""

# Check each common path
for path in "${HOMEBREW_PATHS[@]}"; do
    if [ -x "$path/mysql" ]; then
        MYSQL_FOUND="$path/mysql"
        MYSQL_PATH="$path"
        echo "✅ Found MySQL client at: $MYSQL_FOUND"
        break
    fi
done

if [ -z "$MYSQL_FOUND" ]; then
    echo "❌ MySQL client not found in common Homebrew paths"
    echo ""
    echo "🔍 Let's search your entire system:"
    
    # Search for mysql binary
    SEARCH_RESULT=$(find /opt /usr/local /usr/bin /bin -name "mysql" -type f -executable 2>/dev/null | head -1)
    
    if [ -n "$SEARCH_RESULT" ]; then
        echo "✅ Found MySQL at: $SEARCH_RESULT"
        MYSQL_FOUND="$SEARCH_RESULT"
        MYSQL_PATH=$(dirname "$SEARCH_RESULT")
    else
        echo "❌ MySQL client not found on system"
        echo ""
        echo "Please install MySQL client:"
        echo "  brew install mysql-client"
        echo "  # OR"
        echo "  brew install mysql"
        exit 1
    fi
fi

# Test the MySQL client
echo "🧪 Testing MySQL client..."
if "$MYSQL_FOUND" --version >/dev/null 2>&1; then
    echo "✅ MySQL client is working"
    echo "   Version: $("$MYSQL_FOUND" --version)"
else
    echo "❌ MySQL client found but not working properly"
    exit 1
fi

# Check if path is already in PATH
if echo "$PATH" | grep -q "$MYSQL_PATH"; then
    echo "✅ MySQL path is already in PATH"
else
    echo "⚠️  MySQL path is not in PATH"
    echo ""
    echo "🔧 To add MySQL to your PATH permanently:"
    echo ""
    
    # Detect shell
    SHELL_NAME=$(basename "$SHELL")
    case "$SHELL_NAME" in
        "bash")
            PROFILE_FILE="$HOME/.bash_profile"
            ;;
        "zsh")
            PROFILE_FILE="$HOME/.zshrc"
            ;;
        *)
            PROFILE_FILE="$HOME/.profile"
            ;;
    esac
    
    echo "Add this line to your $PROFILE_FILE:"
    echo "export PATH=\"$MYSQL_PATH:\$PATH\""
    echo ""
    echo "Then run: source $PROFILE_FILE"
    echo ""
    echo "🚀 Or run the setup script with the full path:"
    echo "MYSQL_CLIENT=\"$MYSQL_FOUND\" ./setup-auth.sh"
fi

# Export for current session
export PATH="$MYSQL_PATH:$PATH"
echo ""
echo "✅ MySQL client temporarily added to PATH for this session"
echo "   You can now run: ./setup-auth.sh"
echo ""
echo "🔗 MySQL client location: $MYSQL_FOUND"
echo "📁 MySQL bin directory: $MYSQL_PATH"
