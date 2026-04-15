#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get the exposed port (defaults to 8000)
PORT=${PORT:-8000}

# Print startup banner
echo ""
echo -e "${BLUE}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║                                                            ║${NC}"
echo -e "${BLUE}${BOLD}║${NC}  ${GREEN}${BOLD}actsense - GitHub Actions Security Auditor${NC}${BLUE}${BOLD}                ║${NC}"
echo -e "${BLUE}${BOLD}║${NC}  ${YELLOW}by @0xCardinal${NC}${BLUE}${BOLD}                                            ║${NC}"
echo -e "${BLUE}${BOLD}║                                                            ║${NC}"
echo -e "${BLUE}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}${BOLD}Initializing server...${NC}"
echo ""

# Change to backend directory
cd /app/backend

# Clean up any stale virtual environment to avoid warnings
if [ -d ".venv" ]; then
    rm -rf .venv
fi

# Function to show access information
show_access_info() {
    sleep 3  # Give server time to start
    # Check if server is responding
    for i in {1..10}; do
        if curl -s http://localhost:"$PORT"/api/health > /dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    
    echo ""
    echo -e "${GREEN}${BOLD}✓ Server is ready!${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Access the platform at:${NC}"
    echo ""
    echo -e "  ${BOLD}Local:${NC}    http://localhost:$PORT"
    echo ""
    
    # If running in Docker, provide helpful instructions
    if [ -f /.dockerenv ]; then
        echo -e "${YELLOW}Note: If you're accessing from outside the container:${NC}"
        echo -e "  • Make sure port $PORT is mapped: ${BOLD}docker run -p $PORT:$PORT actsense${NC}"
        echo -e "  • Then navigate to: ${BOLD}http://localhost:$PORT${NC}"
        echo ""
    fi
    
    echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
    echo ""
}

# Show access info in background
show_access_info &

# Start the server with reduced log level to minimize output
exec uv run uvicorn main:app --host 0.0.0.0 --port "$PORT" --log-level warning
