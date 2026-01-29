#!/bin/bash
# run_local.sh - Run both servers locally for testing

cd "$(dirname "$0")"

# Find Python with Flask installed
PYTHON_CMD=""
for cmd in python3 python /Library/Frameworks/Python.framework/Versions/3.11/bin/python3; do
    if $cmd -c "import flask" 2>/dev/null; then
        PYTHON_CMD=$cmd
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "Flask not found. Installing..."
    pip3 install flask requests pyopenssl 2>/dev/null || pip install flask requests pyopenssl
    PYTHON_CMD=python3
fi

echo "Using Python: $PYTHON_CMD"

# Kill any existing processes on ports 5001 and 8080
echo "Cleaning up old processes..."
lsof -ti:5001 | xargs kill -9 2>/dev/null
lsof -ti:8080 | xargs kill -9 2>/dev/null

sleep 1

echo ""
echo "Starting Database Server on port 5001..."
cd database_server
APP_ENV=demo ENABLE_TOTP_TEST_ENDPOINT=true ENABLE_QUERY_CONSOLE=true $PYTHON_CMD app.py &
DB_PID=$!
cd ..

sleep 2

echo ""
echo "Starting Proxy Server on port 8080..."
cd proxy_clone
APP_ENV=demo SSL_VERIFY=false $PYTHON_CMD app.py &
PROXY_PID=$!
cd ..

sleep 2

echo ""
echo "=============================================="
echo "Servers started!"
echo "  Database Server: https://localhost:5001"
echo "  Proxy Server:    https://localhost:8080"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: SecurePass123!"
echo "  Security Answer: blue"
echo ""
echo "Press Ctrl+C to stop both servers"
echo "=============================================="

# Wait for interrupt
trap "kill $DB_PID $PROXY_PID 2>/dev/null; exit 0" INT
wait
