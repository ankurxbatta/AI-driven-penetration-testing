#!/bin/bash

# Exit on any error
set -e

echo "Starting Kali Pentest MCP Server..."
echo "User: $(whoami)"
echo "Working directory: $(pwd)"

# Update exploit database
echo "Updating exploit database..."
searchsploit --update || echo "Warning: Could not update exploit database"

# Test tool availability
echo "Checking tool availability..."
for tool in nmap nikto sqlmap wpscan dirb searchsploit; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "✓ $tool is available"
    else
        echo "✗ $tool is NOT available"
    fi
done

# Start the MCP server
echo "Starting MCP server on port 8000..."
exec /app/venv/bin/python server.py
