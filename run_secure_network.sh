#!/bin/bash
# Complete setup script for secure network

echo "=========================================="
echo "🔐 SECURE NETWORK STARTUP SCRIPT"
echo "=========================================="
echo ""

# Configuration - Update these paths for your system
RYU_VENV="/home/arfa/ryu-venv"
RYU_PYTHON="${RYU_VENV}/bin/python"
RYU_MANAGER="${RYU_VENV}/bin/ryu-manager"
MNEXEC_PATH="/home/arfa/mininet"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Export mnexec path for Mininet
export PATH="${MNEXEC_PATH}:${PATH}"

# Check dependencies
echo "📦 Checking dependencies..."

# Check Ryu virtual environment
if [ ! -f "${RYU_MANAGER}" ]; then
    echo "❌ Ryu not found at ${RYU_MANAGER}"
    echo "   Please install: cd ${RYU_VENV} && pip install ryu"
    exit 1
fi

# Check Mininet
if ! command -v mn >/dev/null 2>&1; then
    echo "❌ Mininet not installed"
    exit 1
fi

# Check mnexec
if [ ! -f "${MNEXEC_PATH}/mnexec" ]; then
    echo "❌ mnexec not found at ${MNEXEC_PATH}/mnexec"
    echo "   Trying system mnexec..."
    if ! command -v mnexec >/dev/null 2>&1; then
        echo "❌ mnexec not found anywhere"
        exit 1
    fi
fi

# Check Python cryptography in Ryu venv
"${RYU_PYTHON}" -c "import cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Cryptography not installed in Ryu venv"
    echo "   Installing now..."
    "${RYU_VENV}/bin/pip" install cryptography
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install cryptography"
        exit 1
    fi
fi

echo "✅ All dependencies found"
echo ""

# Clean up any previous Mininet instances
echo "🧹 Cleaning up previous instances..."
mn -c > /dev/null 2>&1

# Kill any existing Ryu controllers
echo "🔪 Killing existing Ryu controllers..."
pkill -9 -f ryu-manager > /dev/null 2>&1
pkill -9 -f "python.*controller_firewall" > /dev/null 2>&1

sleep 2

# Create policy.json if it doesn't exist
if [ ! -f "${PROJECT_DIR}/policy.json" ]; then
    echo "📝 Creating default policy.json..."
    cat > "${PROJECT_DIR}/policy.json" << 'EOF'
{
  "allow": [
    {"src": "10.0.1.0/24", "dst": "10.0.2.0/24"},
    {"src": "10.0.2.0/24", "dst": "10.0.1.0/24"},
    {"src": "10.0.1.0/24", "dst": "10.0.1.0/24"},
    {"src": "10.0.2.0/24", "dst": "10.0.2.0/24"}
  ],
  "block": []
}
EOF
    echo "✅ policy.json created"
fi

echo ""
echo "=========================================="
echo "Starting Secure Network..."
echo "=========================================="
echo ""

# Change to project directory
cd "${PROJECT_DIR}"

# Start Ryu controller in background
echo "🎮 Starting Ryu Controller..."
"${RYU_MANAGER}" controller_firewall.py --verbose > ryu.log 2>&1 &
RYU_PID=$!

echo "   Ryu PID: ${RYU_PID}"
echo "   Waiting for controller to initialize..."
sleep 4

# Check if Ryu is running
if ps -p ${RYU_PID} > /dev/null; then
    echo "✅ Ryu controller running"
else
    echo "❌ Ryu controller failed to start. Check ryu.log:"
    tail -n 20 ryu.log
    exit 1
fi

echo ""
echo "🌐 Starting Mininet Topology..."
echo ""

# Start Mininet with proper Python from Ryu venv
"${RYU_PYTHON}" topology_with_security.py

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill ${RYU_PID} 2>/dev/null
sleep 1
pkill -9 -f ryu-manager > /dev/null 2>&1
mn -c > /dev/null 2>&1

echo ""
echo "✅ Network stopped successfully"