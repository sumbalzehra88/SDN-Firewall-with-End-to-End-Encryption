#!/bin/bash
# Complete setup script for secure network
# Member 3: Security Integration

echo "=========================================="
echo "🔐 SECURE NETWORK STARTUP SCRIPT"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Check dependencies
echo "📦 Checking dependencies..."
command -v /home/mufeez/ryu-py39/bin/ryu-manager >/dev/null 2>&1 || { echo "❌ Ryu not installed. Run: pip install ryu"; exit 1; }
command -v mn >/dev/null 2>&1 || { echo "❌ Mininet not installed"; exit 1; }
python3 -c "import cryptography" 2>/dev/null || { echo "❌ Cryptography not installed. Run: pip install cryptography"; exit 1; }

echo "✅ All dependencies found"
echo ""

# Clean up any previous Mininet instances
echo "🧹 Cleaning up previous instances..."
mn -c > /dev/null 2>&1

# Kill any existing Ryu controllers
echo "🔪 Killing existing Ryu controllers..."
pkill -9 -f ryu-manager > /dev/null 2>&1

sleep 2

# Create policy.json if it doesn't exist
if [ ! -f policy.json ]; then
    echo "📝 Creating default policy.json..."
    cat > policy.json << 'EOF'
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

# Start Ryu controller in background
echo "🎮 Starting Ryu Controller (Member 2 + 3)..."
/home/mufeez/ryu-py39/bin/ryu-manager controller_firewall.py --verbose > ryu.log 2>&1 &
RYU_PID=$!

echo "   Ryu PID: $RYU_PID"
echo "   Waiting for controller to initialize..."
sleep 3

# Check if Ryu is running
if ps -p $RYU_PID > /dev/null; then
    echo "✅ Ryu controller running"
else
    echo "❌ Ryu controller failed to start. Check ryu.log"
    exit 1
fi

echo ""
echo "🌐 Starting Mininet Topology (Member 1 + 3)..."
echo ""

# Start Mininet
python3 topology_with_security.py

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill $RYU_PID 2>/dev/null
mn -c > /dev/null 2>&1

echo ""
echo "✅ Network stopped successfully"