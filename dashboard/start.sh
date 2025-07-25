#!/bin/bash

# VulcanGuard Dashboard Quick Start
echo "🚀 VulcanGuard Dashboard Quick Start"
echo "==================================="

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Please run this script from the dashboard directory"
    exit 1
fi

# Start the dashboard stack
echo "🐳 Starting VulcanGuard Dashboard..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to initialize..."
sleep 25

echo ""
echo "🎉 Dashboard is ready!"
echo ""
echo "📊 Visualization Frontend:"
echo "   • Grafana Dashboard: http://localhost:3000"
echo "     - Username: admin"
echo "     - Password: vulcanguard123"
echo ""
echo "🗄️  Data Storage Backends:"
echo "   • Prometheus (metrics): http://localhost:9090"
echo "   • InfluxDB (geo/analytics): http://localhost:8086"
echo "   • Node Exporter (system metrics): http://localhost:9100"
echo ""
echo "🔧 VulcanGuard Integration:"
echo "   • Make sure VulcanGuard is running on port 8888"
echo "   • Prometheus metrics: http://localhost:8888/metrics"
echo "   • Geographic data: http://localhost:8888/api/geo-stats"
echo "   • Grafana configured with both Prometheus and InfluxDB data sources"
echo ""
echo "📈 To stop the dashboard:"
echo "   docker-compose down"
echo ""
echo "📖 For detailed setup instructions, see README.md"
