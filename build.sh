#!/bin/bash

# VulcanGuard Build Script
echo "🛡️ Building VulcanGuard..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go 1.22.0 or later."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
REQUIRED_VERSION="1.22"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    print_error "Go version $REQUIRED_VERSION or later is required. Found: $GO_VERSION"
    exit 1
fi

print_status "Go version check passed: $GO_VERSION"

# Clean previous builds
print_status "Cleaning previous builds..."
rm -f vulcanguard-enhanced vulcanguard-demo

# Initialize and tidy modules
print_status "Initializing Go modules..."
go mod tidy

# Check if we need to initialize submodules
for dir in BehavioralProfiler TrafficAnalyser P2P IdentityAnalyzer; do
    if [ -d "$dir" ]; then
        cd "$dir"
        if [ ! -f "go.mod" ]; then
            print_warning "Initializing module for $dir"
            go mod init "Suboptimal/Firewall/$dir"
        fi
        go mod tidy
        cd ..
    fi
done

print_status "Module initialization complete"

# Build the enhanced version
print_status "Building VulcanGuard..."
if go build -o vulcanguard main.go; then
    print_status "Enhanced version built successfully: vulcanguard-enhanced"
else
    print_error "Failed to build VulcanGuard"
    exit 1
fi

# Build the demo
print_status "Building demo application..."
if go build -o vg-demo demo.go; then
    print_status "Demo application built successfully: vg-demo"
else
    print_warning "Failed to build demo application (non-critical)"
fi

# Build original version for comparison
print_status "Building original version..."
if go build -o vulcanguard-original main.go; then
    print_status "Original version built successfully: vulcanguard-original"
else
    print_warning "Failed to build original version (non-critical)"
fi

# Check for required system capabilities
print_status "Checking system requirements..."

# Check for XDP/eBPF support
if [ ! -d "/sys/fs/bpf" ]; then
    print_warning "BPF filesystem not mounted. XDP features may not work."
    print_warning "To enable, run: sudo mount -t bpf bpf /sys/fs/bpf"
fi

# Check for network capabilities
if [ "$EUID" -ne 0 ]; then
    print_warning "Not running as root. Some network features may require elevated privileges."
fi

# Display build summary
echo ""
echo "🏗️ Build Summary"
echo "=================="
echo "✅ VulcanGuard Enhanced: vulcanguard-enhanced"
[ -f "vulcanguard-demo" ] && echo "✅ Demo Application: vulcanguard-demo"
[ -f "vulcanguard-original" ] && echo "✅ Original Version: vulcanguard-original"
echo ""

# Display usage instructions
echo "🚀 Usage Instructions"
echo "====================="
echo ""
echo "Run Enhanced VulcanGuard:"
echo "  sudo ./vulcanguard-enhanced"
echo ""
echo "Run Demo (no sudo required):"
echo "  ./vulcanguard-demo"
echo ""
echo "View Enhanced Features Documentation:"
echo "  cat ENHANCED_FEATURES.md"
echo ""

# Display feature summary
echo "🛡️ Enhanced Features Included"
echo "============================="
echo "✅ Behavioral Profiling System"
echo "✅ Advanced Traffic Analysis" 
echo "✅ P2P Threat Intelligence Sharing"
echo "✅ Identity Analysis & Adaptive Screening"
echo "✅ Multi-layer DDoS Protection"
echo "✅ Real-time Attack Pattern Detection"
echo ""

# Display ports and endpoints
echo "🌐 Network Configuration"
echo "========================"
echo "Main Service Port: 8080"
echo "P2P Network Port: 9001"
echo "Health Check: http://localhost:8080/health"
echo "P2P Status: http://localhost:9001/p2p/health"
echo ""

print_status "Build complete! VulcanGuard Enhanced is ready to deploy."
echo ""
echo "📚 Next Steps:"
echo "1. Review ENHANCED_FEATURES.md for detailed documentation"
echo "2. Configure your backend servers in LoadB/lb.go"
echo "3. Set up P2P peer connections if running multiple nodes"
echo "4. Monitor logs in Firewall.log for security events"
echo ""
echo "Happy protecting! 🛡️✨"
