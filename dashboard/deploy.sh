#!/bin/bash

# VulcanGuard Dashboard Deployment Script
echo "🚀 Starting VulcanGuard Dashboard Deployment..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating required directories..."
mkdir -p ./data/prometheus
mkdir -p ./data/grafana
mkdir -p ./data/influxdb

# Set permissions
echo "🔐 Setting permissions..."
sudo chown -R 472:472 ./data/grafana  # Grafana user
sudo chown -R 65534:65534 ./data/prometheus  # Nobody user for Prometheus

# Start the dashboard stack
echo "🐳 Starting Docker containers..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check service health
echo "🏥 Checking service health..."
if curl -f http://localhost:9090 &> /dev/null; then
    echo "✅ Prometheus is healthy"
else
    echo "⚠️  Prometheus might not be ready yet"
fi

if curl -f http://localhost:8086/health &> /dev/null; then
    echo "✅ InfluxDB is healthy"
else
    echo "⚠️  InfluxDB might not be ready yet"
fi

if curl -f http://localhost:3000 &> /dev/null; then
    echo "✅ Grafana is healthy"
else
    echo "⚠️  Grafana might not be ready yet"
fi

if curl -f http://localhost:9100/metrics &> /dev/null; then
    echo "✅ Node Exporter is healthy"
else
    echo "⚠️  Node Exporter might not be ready yet"
fi

echo ""
echo "🎉 VulcanGuard Dashboard deployed successfully!"
echo ""
echo "📊 Visualization Frontend:"
echo "   • Grafana: http://localhost:3000 (admin/vulcanguard123)"
echo ""
echo "🗄️  Data Storage Backends:"
echo "   • Prometheus: http://localhost:9090 (metrics & time-series)"
echo "   • InfluxDB: http://localhost:8086 (geolocation & analytics)"
echo "   • Node Exporter: http://localhost:9100 (system metrics)"
echo ""
echo "🔧 Architecture:"
echo "   • Single visualization layer: Grafana"
echo "   • Multiple data sources: Prometheus + InfluxDB + Node Exporter"
echo "   • VulcanGuard feeds application data to Prometheus/InfluxDB"
echo "   • Node Exporter provides host system metrics"
echo "   • Grafana combines all sources for comprehensive dashboards"
echo ""
echo "📖 For more information, see README.md"
