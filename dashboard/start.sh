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
sleep 20

echo ""
echo "🎉 Dashboard is ready!"
echo ""
echo "📊 Access URLs:"
echo "   • Grafana Dashboard: http://localhost:3000"
echo "     - Username: admin"
echo "     - Password: vulcanguard123"
echo ""
echo "   • Prometheus Metrics: http://localhost:9090"
echo "   • InfluxDB Interface: http://localhost:8086"
echo ""
echo "🔧 API Endpoints:"
echo "   • VulcanGuard Stats: http://localhost:8888/api/stats"
echo "   • Geographic Data: http://localhost:8888/api/geo-stats"
echo "   • Prometheus Metrics: http://localhost:8888/metrics"
echo ""
echo "📈 To stop the dashboard:"
echo "   docker-compose down"
echo ""
echo "📖 For detailed setup instructions, see README.md"
