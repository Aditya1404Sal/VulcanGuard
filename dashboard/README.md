# VulcanGuard Dashboard

A comprehensive monitoring and visualization dashboard for VulcanGuard Firewall, featuring real-time traffic analysis, geolocation mapping, behavioral profiling, and distributed threat intelligence.

## 🌟 Features

### Real-time Monitoring
- **Traffic Flow Visualization**: Monitor incoming/outgoing traffic in real-time
- **Geographic Traffic Mapping**: See global traffic patterns on an interactive world map
- **Load Balancing Metrics**: Track load distribution and server performance
- **Security Events**: Real-time alerts for attacks, anomalies, and security events

### Advanced Analytics
- **Behavioral Profiling**: Detect anomalous user behavior patterns
- **Geolocation Intelligence**: Track and analyze traffic by country, city, and coordinates
- **P2P Network Status**: Monitor distributed threat intelligence sharing
- **Attack Pattern Recognition**: Identify DDoS, brute force, and coordinated attacks

### Dashboard Components
- **Grafana**: Primary visualization platform with custom dashboards
- **Prometheus**: Metrics collection and alerting
- **InfluxDB**: Time-series data storage for geolocation and traffic data
- **Redis**: Real-time caching and session storage
- **Custom Exporter**: VulcanGuard-specific metrics collector

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- VulcanGuard Firewall running on port 8888
- At least 4GB RAM for all services

### Deployment

1. **Clone and navigate to dashboard directory**:
   ```bash
   cd dashboard
   ```

2. **Deploy the dashboard stack**:
   ```bash
   ./deploy.sh
   ```

3. **Access dashboards**:
   - **Grafana**: http://localhost:3000 (admin/vulcanguard123)
   - **Prometheus**: http://localhost:9090
   - **InfluxDB**: http://localhost:8086

## 📊 Dashboard Overview

### Main Dashboard (Grafana)
The primary VulcanGuard dashboard includes:

1. **Request Rate Overview**
   - Total requests per second
   - Blocked vs. allowed requests
   - Real-time rate monitoring

2. **Global Traffic Map**
   - Interactive world map showing traffic origins
   - Color-coded threat levels by region
   - Click-to-zoom geographic analysis

3. **Security Metrics**
   - Active connections counter
   - Blacklisted IPs gauge
   - Real-time threat indicators

4. **Behavioral Analysis**
   - Anomaly detection graphs
   - Behavioral pattern matching
   - User similarity analysis

5. **P2P Network Status**
   - Active peer connections
   - Threat intelligence sharing metrics
   - Network health indicators

### Geographic Visualization
- Real-time traffic plotting on world map
- Country-based traffic statistics
- City-level geographic resolution
- Threat density heatmaps

## 🔧 Configuration

### Environment Variables

#### VulcanGuard Exporter
```bash
VULCANGUARD_API_URL=http://host.docker.internal:8888
REDIS_URL=redis:6379
INFLUXDB_URL=http://influxdb:8086
INFLUXDB_TOKEN=vulcanguard-super-secret-auth-token
INFLUXDB_ORG=vulcanguard
INFLUXDB_BUCKET=firewall_metrics
```

#### Grafana
```bash
GF_SECURITY_ADMIN_PASSWORD=vulcanguard123
GF_USERS_ALLOW_SIGN_UP=false
GF_INSTALL_PLUGINS=grafana-worldmap-panel,grafana-piechart-panel,grafana-geomap-panel
```

#### InfluxDB
```bash
DOCKER_INFLUXDB_INIT_USERNAME=vulcanguard
DOCKER_INFLUXDB_INIT_PASSWORD=vulcanguard123
DOCKER_INFLUXDB_INIT_ORG=vulcanguard
DOCKER_INFLUXDB_INIT_BUCKET=firewall_metrics
```

### Custom Metrics

VulcanGuard exposes these Prometheus metrics:

- `vulcanguard_requests_total`: Total processed requests
- `vulcanguard_blocked_requests_total`: Total blocked requests
- `vulcanguard_allowed_requests_total`: Total allowed requests
- `vulcanguard_active_connections`: Current active connections
- `vulcanguard_blacklisted_ips`: Number of blacklisted IPs
- `vulcanguard_requests_by_country`: Requests grouped by country
- `vulcanguard_behavioral_anomalies_total`: Behavioral anomalies detected
- `vulcanguard_similarity_matches_total`: Similar behavior patterns found
- `vulcanguard_p2p_active_peers`: Active P2P network peers
- `vulcanguard_p2p_shared_threats`: Threats shared via P2P network

## 📈 Monitoring and Alerts

### Prometheus Alerts
Pre-configured alerts for:
- High request rates (>100 req/sec)
- Possible DDoS attacks (>50 blocked req/sec)
- High error rates (>10%)
- Suspicious geographic activity
- Behavioral anomalies
- P2P network health issues

### Alert Rules Location
```
prometheus/rules/vulcanguard.yml
```

## 🗂️ Data Storage

### Time-series Data (InfluxDB)
- Geographic request data with coordinates
- Traffic patterns over time
- Performance metrics
- Security event timelines

### Caching (Redis)
- Real-time geolocation data
- Session information
- Temporary blacklist data
- P2P network state

### Metrics (Prometheus)
- Application performance metrics
- System resource usage
- Security event counters
- Alert rule evaluation

## 🔧 API Endpoints

### VulcanGuard Exporter API
- `GET /metrics`: Prometheus metrics endpoint
- `GET /api/geo-data`: Current geographic traffic data
- `GET /health`: Service health check

### Expected VulcanGuard API
The dashboard expects these endpoints from VulcanGuard:
- `GET /api/stats`: Basic firewall statistics
- `GET /api/geo-stats`: Geographic traffic breakdown
- `GET /metrics`: Prometheus metrics (if available)

## 🛠️ Customization

### Adding Custom Dashboards
1. Create JSON dashboard files in `grafana/dashboards/`
2. Restart Grafana service
3. Dashboards will be automatically imported

### Custom Metrics
Add new metrics in `exporter/main.go`:
```go
customMetric := prometheus.NewGauge(prometheus.GaugeOpts{
    Name: "vulcanguard_custom_metric",
    Help: "Description of custom metric",
})
prometheus.MustRegister(customMetric)
```

### Geographic Data Sources
Modify `updateMetrics()` in the exporter to pull data from different geolocation APIs or databases.

## 🐳 Docker Services

| Service | Port | Purpose |
|---------|------|---------|
| Grafana | 3000 | Main dashboard interface |
| Prometheus | 9090 | Metrics collection and alerting |
| InfluxDB | 8086 | Time-series data storage |
| Redis | 6379 | Real-time caching |
| VulcanGuard Exporter | 8080 | Custom metrics collector |
| Node Exporter | 9100 | System metrics |

## 🔒 Security Considerations

### Default Credentials
- **Grafana**: admin/vulcanguard123
- **InfluxDB**: vulcanguard/vulcanguard123

⚠️ **Important**: Change default passwords in production!

### Network Security
- All services run in isolated Docker network
- Expose only necessary ports
- Use environment variables for sensitive data

### Data Privacy
- Geographic data aggregated by city/country
- No personal information stored
- IP addresses hashed for analytics

## 🚨 Troubleshooting

### Common Issues

1. **Services not starting**:
   ```bash
   docker-compose logs [service-name]
   ```

2. **VulcanGuard connection failed**:
   - Ensure VulcanGuard is running on port 8888
   - Check firewall rules
   - Verify API endpoints are accessible

3. **Grafana dashboards not loading**:
   - Check Prometheus data source connection
   - Verify metrics are being collected
   - Review Grafana logs

4. **Geographic data not showing**:
   - Confirm InfluxDB is receiving data
   - Check VulcanGuard geo-stats API
   - Verify exporter is running

### Logs and Debugging
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f grafana
docker-compose logs -f prometheus
docker-compose logs -f vulcanguard-exporter
```

## 📊 Performance Tuning

### Resource Requirements
- **Minimum**: 4GB RAM, 2 CPU cores
- **Recommended**: 8GB RAM, 4 CPU cores
- **Storage**: 20GB for logs and time-series data

### Optimization
- Adjust scrape intervals in `prometheus.yml`
- Configure retention policies in InfluxDB
- Tune Redis memory limits
- Optimize Grafana refresh rates

## 🔄 Backup and Recovery

### Data Backup
```bash
# Backup InfluxDB data
docker exec vulcanguard-influxdb influx backup /backup

# Backup Grafana dashboards
docker exec vulcanguard-grafana cp -r /var/lib/grafana/dashboards /backup

# Backup Prometheus data
docker exec vulcanguard-prometheus cp -r /prometheus /backup
```

### Restore Procedure
1. Stop services: `docker-compose down`
2. Restore data volumes
3. Start services: `docker-compose up -d`

## 📚 Additional Resources

- [Grafana Documentation](https://grafana.com/docs/)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [InfluxDB Time Series](https://docs.influxdata.com/)
- [VulcanGuard Main Documentation](../USAGE_GUIDE.md)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add/modify dashboard components
4. Test with sample data
5. Submit pull request

## 📝 License

This dashboard is part of the VulcanGuard project and follows the same licensing terms.
