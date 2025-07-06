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
mkdir -p ./data/redis
mkdir -p ./data/elasticsearch

# Set permissions
echo "🔐 Setting permissions..."
sudo chown -R 472:472 ./data/grafana  # Grafana user
sudo chown -R 65534:65534 ./data/prometheus  # Nobody user for Prometheus

# Build custom exporter
echo "🔨 Building VulcanGuard exporter..."
cd exporter
go mod tidy
cd ..

# Start the dashboard stack
echo "🐳 Starting Docker containers..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check service health
echo "🏥 Checking service health..."
services=("prometheus:9090" "grafana:3000" "influxdb:8086" "redis:6379" "vulcanguard-exporter:8080")

for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    if curl -f http://localhost:$port/health &> /dev/null || curl -f http://localhost:$port &> /dev/null; then
        echo "✅ $name is healthy"
    else
        echo "⚠️  $name might not be ready yet"
    fi
done

echo ""
echo "🎉 VulcanGuard Dashboard deployed successfully!"
echo ""
echo "📊 Access your dashboards:"
echo "   • Grafana: http://localhost:3000 (admin/vulcanguard123)"
echo "   • Prometheus: http://localhost:9090"
echo "   • InfluxDB: http://localhost:8086"
echo ""
echo "🔧 API Endpoints:"
echo "   • Metrics: http://localhost:8080/metrics"
echo "   • Geo Data: http://localhost:8080/api/geo-data"
echo "   • Health: http://localhost:8080/health"
echo ""
echo "📖 For more information, see README.md"
