#!/bin/bash
#==============================================================================
# run.sh - Run Database Server & Proxy Clone
#
# Usage:
#   ./scripts/run.sh          # Run with Docker (default)
#   ./scripts/run.sh docker   # Run with Docker
#   ./scripts/run.sh local    # Run locally with Python
#   ./scripts/run.sh stop     # Stop all running instances
#   ./scripts/run.sh logs     # Show Docker logs
#   ./scripts/run.sh test     # Test if servers are running
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Change to project root (script lives in ./scripts)
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

# Configuration
DB_PORT_LOCAL=5001
DB_PORT_DOCKER=5002
PROXY_PORT=8080

print_header() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
}

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${YELLOW}→ $1${NC}"; }

ensure_demo_certs() {
    print_info "Ensuring local demo TLS certificates exist..."
    bash "$SCRIPT_DIR/scripts/generate_demo_certs.sh"
}

#------------------------------------------------------------------------------
# Docker Mode
#------------------------------------------------------------------------------
run_docker() {
    print_header "Starting with Docker"

    # Check Docker
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker Desktop."
        exit 1
    fi
    print_success "Docker is running"

    ensure_demo_certs

    print_info "Building and starting containers..."
    docker-compose down --remove-orphans 2>/dev/null
    docker-compose up --build -d

    print_info "Waiting for containers to start..."
    sleep 5

    # Check containers
    if docker ps | grep -q "database-server"; then
        print_success "Database Server is running"
    else
        print_error "Database Server failed to start"
        docker-compose logs database-server
        exit 1
    fi

    if docker ps | grep -q "proxy-clone"; then
        print_success "Proxy Clone is running"
    else
        print_error "Proxy Clone failed to start"
        docker-compose logs proxy-clone
        exit 1
    fi

    print_header "Servers Started Successfully!"
    echo ""
    echo -e "  ${GREEN}Database Server (HTTPS):${NC} https://localhost:$DB_PORT_DOCKER"
    echo -e "  ${GREEN}Proxy Clone (HTTPS):${NC}     https://localhost:$PROXY_PORT"
    echo ""
    echo -e "  ${YELLOW}Default Credentials:${NC}"
    echo "    Username: admin"
    echo "    Password: SecurePass123!"
    echo "    Security Answer: blue"
    echo ""
    echo -e "  ${YELLOW}Commands:${NC}"
    echo "    ./scripts/run.sh logs   - View container logs"
    echo "    ./scripts/run.sh stop   - Stop containers"
    echo "    ./scripts/run.sh test   - Test if servers are responding"
    echo ""

    # Show TOTP info
    print_info "Fetching TOTP codes from logs..."
    sleep 2
    docker-compose logs database-server 2>&1 | grep -A5 "2FA SETUP" || echo "  (TOTP info will appear after first database init)"
}

stop_docker() {
    print_header "Stopping Docker Containers"
    docker-compose down --remove-orphans 2>/dev/null
    print_success "Containers stopped"
}

show_logs() {
    print_header "Docker Logs"
    docker-compose logs --tail=50 -f
}

#------------------------------------------------------------------------------
# Local Mode
#------------------------------------------------------------------------------
run_local() {
    print_header "Starting Locally (without Docker)"

    ensure_demo_certs

    # Kill existing processes
    print_info "Stopping any running local processes..."
    lsof -ti:$DB_PORT_LOCAL 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:$PROXY_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 1

    # Find Python with Flask
    PYTHON_CMD=""
    for cmd in /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 python3 python; do
        if command -v "$cmd" > /dev/null 2>&1; then
            if "$cmd" -c "import flask" 2>/dev/null; then
                PYTHON_CMD="$cmd"
                break
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        print_info "Flask not found. Installing dependencies..."
        pip3 install flask requests pyopenssl 2>/dev/null || pip install flask requests pyopenssl
        PYTHON_CMD="python3"
    fi

    print_success "Using Python: $PYTHON_CMD"

    # Start Database Server
    print_info "Starting Database Server on port $DB_PORT_LOCAL..."
    cd "$SCRIPT_DIR"
    APP_ENV=demo ENABLE_TOTP_TEST_ENDPOINT=true ENABLE_QUERY_CONSOLE=true "$PYTHON_CMD" -m database_server.app > /tmp/db_server.log 2>&1 &
    DB_PID=$!

    sleep 3

    if ! kill -0 $DB_PID 2>/dev/null; then
        print_error "Database Server failed to start. Check logs:"
        cat /tmp/db_server.log
        exit 1
    fi
    print_success "Database Server started (PID: $DB_PID)"

    # Start Proxy Server
    print_info "Starting Proxy Server on port $PROXY_PORT..."
    cd "$SCRIPT_DIR"
    APP_ENV=demo SSL_VERIFY=false "$PYTHON_CMD" -m proxy_clone.app > /tmp/proxy_server.log 2>&1 &
    PROXY_PID=$!

    sleep 2

    if ! kill -0 $PROXY_PID 2>/dev/null; then
        print_error "Proxy Server failed to start. Check logs:"
        cat /tmp/proxy_server.log
        kill $DB_PID 2>/dev/null
        exit 1
    fi
    print_success "Proxy Server started (PID: $PROXY_PID)"

    print_header "Servers Started Successfully!"
    echo ""
    echo -e "  ${GREEN}Database Server (HTTPS):${NC} https://localhost:$DB_PORT_LOCAL"
    echo -e "  ${GREEN}Proxy Clone (HTTPS):${NC}     https://localhost:$PROXY_PORT"
    echo ""
    echo -e "  ${YELLOW}Default Credentials:${NC}"
    echo "    Username: admin"
    echo "    Password: SecurePass123!"
    echo "    Security Answer: blue"
    echo ""
    echo -e "  ${YELLOW}Log Files:${NC}"
    echo "    Database Server: /tmp/db_server.log"
    echo "    Proxy Server:    /tmp/proxy_server.log"
    echo ""
    echo "  Press Ctrl+C to stop both servers"
    echo ""

    # Show TOTP codes
    print_info "TOTP Codes (from log):"
    sleep 1
    grep -A5 "2FA SETUP" /tmp/db_server.log 2>/dev/null || echo "  (check /tmp/db_server.log for TOTP codes)"

    # Trap Ctrl+C
    trap "echo ''; print_info 'Stopping servers...'; kill $DB_PID $PROXY_PID 2>/dev/null; print_success 'Servers stopped'; exit 0" INT

    # Wait
    wait
}

stop_local() {
    print_header "Stopping Local Processes"
    lsof -ti:$DB_PORT_LOCAL 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:$PROXY_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    print_success "Local processes stopped"
}

#------------------------------------------------------------------------------
# Test Mode
#------------------------------------------------------------------------------
test_servers() {
    print_header "Testing Servers"
    echo ""

    print_info "Testing Database Server..."

    # Try HTTPS Docker port first
    DB_RESPONSE=""
    if curl -s -k -m 3 "https://localhost:$DB_PORT_DOCKER/api/health" 2>/dev/null | grep -q "healthy"; then
        DB_RESPONSE=$(curl -s -k -m 3 "https://localhost:$DB_PORT_DOCKER/api/health" 2>/dev/null)
        print_success "Database Server (HTTPS:$DB_PORT_DOCKER) is running"
        echo "    Response: $DB_RESPONSE"
    # Try HTTPS local port
    elif curl -s -k -m 3 "https://localhost:$DB_PORT_LOCAL/api/health" 2>/dev/null | grep -q "healthy"; then
        DB_RESPONSE=$(curl -s -k -m 3 "https://localhost:$DB_PORT_LOCAL/api/health" 2>/dev/null)
        print_success "Database Server (HTTPS:$DB_PORT_LOCAL) is running"
        echo "    Response: $DB_RESPONSE"
    # Try HTTP local port
    elif curl -s -m 3 "http://localhost:$DB_PORT_LOCAL/api/health" 2>/dev/null | grep -q "healthy"; then
        DB_RESPONSE=$(curl -s -m 3 "http://localhost:$DB_PORT_LOCAL/api/health" 2>/dev/null)
        print_success "Database Server (HTTP:$DB_PORT_LOCAL) is running"
        echo "    Response: $DB_RESPONSE"
    else
        print_error "Database Server is not responding"
    fi

    echo ""
    print_info "Testing Proxy Server..."

    if curl -s -k -m 3 "https://localhost:$PROXY_PORT/api/health" 2>/dev/null | grep -q "\"status\""; then
        PROXY_RESPONSE=$(curl -s -k -m 3 "https://localhost:$PROXY_PORT/api/health" 2>/dev/null)
        print_success "Proxy Server (HTTPS:$PROXY_PORT) is running"
        echo "    Response: $PROXY_RESPONSE"
    else
        print_error "Proxy Server is not responding"
    fi

    echo ""
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
case "${1:-docker}" in
    docker)
        run_docker
        ;;
    local)
        run_local
        ;;
    stop)
        stop_docker
        stop_local
        ;;
    logs)
        show_logs
        ;;
    test)
        test_servers
        ;;
    -h|--help|help)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  docker   Run with Docker (default)"
        echo "  local    Run locally with Python"
        echo "  stop     Stop all running instances"
        echo "  logs     Show Docker logs (follow mode)"
        echo "  test     Test if servers are responding"
        echo "  help     Show this help message"
        echo ""
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
