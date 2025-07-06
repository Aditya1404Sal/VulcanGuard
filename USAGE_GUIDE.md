# VulcanGuard Enhanced - Complete Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Installation & Setup](#installation--setup)
3. [Basic Usage](#basic-usage)
4. [Advanced Configuration](#advanced-configuration)
5. [Multi-Node P2P Setup](#multi-node-p2p-setup)
6. [Monitoring & Logging](#monitoring--logging)
7. [API Reference](#api-reference)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)
10. [Security Best Practices](#security-best-practices)

---

## Quick Start

### Prerequisites
- Go 1.22.0 or later
- Linux system with eBPF/XDP support
- Root privileges (for packet filtering)
- Network access for P2P functionality

### 30-Second Setup
```bash
# Clone and build
cd VulcanGuard/
./build_enhanced.sh

# Run with default settings
sudo ./vulcanguard-enhanced
```

Your enhanced firewall is now running on:
- **Main Service**: `http://localhost:8080`
- **P2P Network**: `http://localhost:9001`
- **Health Check**: `http://localhost:8080/health`

---

## Installation & Setup

### System Requirements

#### Minimum Requirements
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, or equivalent)
- **Memory**: 512MB RAM
- **CPU**: 1 vCPU
- **Network**: 100Mbps connection
- **Kernel**: 4.15+ with eBPF support

#### Recommended Requirements
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+)
- **Memory**: 2GB RAM
- **CPU**: 2+ vCPUs
- **Network**: 1Gbps+ connection
- **Storage**: 10GB for logs and intelligence cache

### Step-by-Step Installation

#### 1. System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y build-essential git curl

# Install Go 1.22.0+
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 2. eBPF/XDP Setup
```bash
# Check kernel support
uname -r  # Should be 4.15+

# Mount BPF filesystem (required for XDP)
sudo mount -t bpf bpf /sys/fs/bpf

# Make permanent
echo 'bpf /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab
```

#### 3. Build VulcanGuard Enhanced
```bash
# Navigate to project directory
cd /home/aditya-sal/Desktop/SystemBackend/VulcanGuard

# Run build script
./build_enhanced.sh

# Verify build
ls -la vulcanguard-*
```

#### 4. Initial Configuration
```bash
# Create directories for logs and data
sudo mkdir -p /var/log/vulcanguard
sudo mkdir -p /var/lib/vulcanguard

# Set permissions
sudo chown $USER:$USER /var/log/vulcanguard
sudo chown $USER:$USER /var/lib/vulcanguard
```

---

## Basic Usage

### Starting VulcanGuard Enhanced

#### Single Node (Standalone)
```bash
# Basic startup
sudo ./vulcanguard-enhanced

# With custom configuration
sudo ./vulcanguard-enhanced \
  --port 8080 \
  --p2p-port 9001 \
  --log-level info \
  --config-file config.yaml
```

#### Daemon Mode (Background Service)
```bash
# Create systemd service
sudo tee /etc/systemd/system/vulcanguard.service > /dev/null <<EOF
[Unit]
Description=VulcanGuard Enhanced DDoS Protection
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/aditya-sal/Desktop/SystemBackend/VulcanGuard
ExecStart=/home/aditya-sal/Desktop/SystemBackend/VulcanGuard/vulcanguard-enhanced
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable vulcanguard
sudo systemctl start vulcanguard
sudo systemctl status vulcanguard
```

### Testing the Setup

#### 1. Health Check
```bash
# Check main service
curl http://localhost:8080/health

# Expected response:
# {"status": "healthy", "node_id": "vulcan-node-xyz", "total_requests": 0, "unique_ips": 0}
```

#### 2. P2P Network Status
```bash
# Check P2P health
curl http://localhost:9001/p2p/health

# Expected response:
# {"node_id": "vulcan-node-xyz", "status": "healthy", "timestamp": "...", "peer_count": 0}
```

#### 3. Load Test
```bash
# Install testing tools
sudo apt install -y apache2-utils

# Simple load test
ab -n 100 -c 10 http://localhost:8080/

# Monitor logs
tail -f Firewall.log
```

---

## Advanced Configuration

### Configuration Files

#### Main Configuration (`config.yaml`)
```yaml
# VulcanGuard Enhanced Configuration
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

rate_limiting:
  max_requests: 20
  tracking_duration: 20s
  brownlist_duration: 25s

behavioral_profiler:
  similarity_threshold: 0.85
  max_profile_age: 24h
  analysis_queue_size: 1000

traffic_analyzer:
  detection_duration: 20s
  max_requests: 20
  spike_multiplier: 3.0
  baseline_window: 24h

p2p_network:
  port: 9001
  sync_interval: 5m
  node_id: "auto"  # auto-generate or specify
  peers:
    - id: "peer1"
      address: "10.0.0.2"
      port: "9001"
    - id: "peer2"  
      address: "10.0.0.3"
      port: "9001"

identity_analyzer:
  similarity_threshold: 0.80
  adaptive_weighting: true
  max_identities: 10000

load_balancer:
  algorithm: "lc"  # "lc" (least connections) or "rr" (round robin)
  servers:
    - "https://www.youtube.com/"
    - "https://wasmcloud.com/"
    - "https://x.com/"

logging:
  level: "info"  # debug, info, warn, error
  file: "Firewall.log"
  max_size: 100MB
  max_files: 10
```

### Environment Variables
```bash
# Core settings
export VULCAN_PORT=8080
export VULCAN_P2P_PORT=9001
export VULCAN_NODE_ID="my-custom-node"

# Rate limiting
export VULCAN_RATE_LIMIT=20
export VULCAN_TRACKING_DURATION=20s

# Behavioral profiler
export VULCAN_SIMILARITY_THRESHOLD=0.85
export VULCAN_MAX_PROFILE_AGE=24h

# Logging
export VULCAN_LOG_LEVEL=info
export VULCAN_LOG_FILE="/var/log/vulcanguard/firewall.log"

# Start with environment config
sudo -E ./vulcanguard-enhanced
```

### Runtime Configuration via API

#### Update Rate Limits
```bash
curl -X POST http://localhost:8080/api/config/rate-limit \
  -H "Content-Type: application/json" \
  -d '{"max_requests": 30, "tracking_duration": "30s"}'
```

#### Add Backend Servers
```bash
curl -X POST http://localhost:8080/api/config/servers \
  -H "Content-Type: application/json" \
  -d '{"servers": ["https://example.com", "https://backup.com"]}'
```

---

## Multi-Node P2P Setup

### Network Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Node A        │◄──►│   Node B        │◄──►│   Node C        │
│   Web Server    │    │   API Server    │    │   CDN Edge      │
│   10.0.0.10     │    │   10.0.0.20     │    │   10.0.0.30     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              P2P Mesh Network                 │
         └───────────────────────┼───────────────────────┘
                                 │
                    Shared Threat Intelligence
```

### Node A Setup (Primary)
```bash
# config-node-a.yaml
server:
  port: 8080
p2p_network:
  port: 9001
  node_id: "node-a-web"
  peers: []  # Will discover peers dynamically

# Start Node A
sudo ./vulcanguard-enhanced --config config-node-a.yaml
```

### Node B Setup (Secondary)
```bash
# config-node-b.yaml
server:
  port: 8080
p2p_network:
  port: 9001
  node_id: "node-b-api"
  peers:
    - id: "node-a-web"
      address: "10.0.0.10"
      port: "9001"

# Start Node B
sudo ./vulcanguard-enhanced --config config-node-b.yaml
```

### Node C Setup (Edge)
```bash
# config-node-c.yaml
server:
  port: 8080
p2p_network:
  port: 9001
  node_id: "node-c-edge"
  peers:
    - id: "node-a-web"
      address: "10.0.0.10"
      port: "9001"
    - id: "node-b-api"
      address: "10.0.0.20" 
      port: "9001"

# Start Node C
sudo ./vulcanguard-enhanced --config config-node-c.yaml
```

### P2P Network Management

#### Add Peer Manually
```bash
curl -X POST http://localhost:9001/p2p/peers \
  -H "Content-Type: application/json" \
  -d '{
    "id": "new-peer",
    "address": "10.0.0.40",
    "port": "9001"
  }'
```

#### Check Peer Status
```bash
curl http://localhost:9001/p2p/peers
```

#### Sync Threat Intelligence
```bash
curl http://localhost:9001/p2p/sync?since=2025-07-01T00:00:00Z
```

---

## Monitoring & Logging

### Log Files Structure

```
/var/log/vulcanguard/
├── firewall.log              # Main application log
├── behavioral-profiler.log   # Behavioral analysis events
├── traffic-analyzer.log      # Traffic analysis and alerts
├── p2p-network.log          # P2P communication logs
├── identity-analyzer.log    # Identity analysis events
└── access.log               # HTTP access logs
```

### Key Log Events

#### Security Events
```bash
# Watch for attacks in real-time
tail -f /var/log/vulcanguard/firewall.log | grep -E "(blacklisted|attack|spike)"

# Filter by severity
tail -f /var/log/vulcanguard/firewall.log | grep "CRITICAL\|HIGH"
```

#### Behavioral Analysis
```bash
# Monitor behavioral profiling
tail -f /var/log/vulcanguard/behavioral-profiler.log

# Watch for coordinated attacks
grep "coordinated attack" /var/log/vulcanguard/*.log
```

#### P2P Network Health
```bash
# Monitor peer connections
tail -f /var/log/vulcanguard/p2p-network.log | grep -E "(peer|sync|intelligence)"

# Check threat intelligence sharing
grep "shared threat intelligence" /var/log/vulcanguard/p2p-network.log
```

### Metrics and Monitoring

#### Built-in Metrics Endpoint
```bash
# Get system metrics
curl http://localhost:8080/metrics

# Example response:
{
  "requests_total": 15420,
  "requests_blocked": 342,
  "unique_ips": 1205,
  "blacklisted_ips": 23,
  "active_profiles": 1180,
  "p2p_peers": 2,
  "threat_intelligence_count": 156,
  "uptime_seconds": 86400
}
```

#### Integration with Monitoring Systems

##### Prometheus
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'vulcanguard'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

##### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "VulcanGuard Enhanced Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [{"expr": "rate(vulcan_requests_total[5m])"}]
      },
      {
        "title": "Block Rate", 
        "targets": [{"expr": "rate(vulcan_requests_blocked[5m])"}]
      },
      {
        "title": "Active Threats",
        "targets": [{"expr": "vulcan_blacklisted_ips"}]
      }
    ]
  }
}
```

### Alerting Setup

#### Email Alerts
```bash
# Install mail utilities
sudo apt install -y mailutils

# Configure alert script
cat > /usr/local/bin/vulcan-alert.sh << 'EOF'
#!/bin/bash
ALERT_TYPE=$1
SEVERITY=$2
MESSAGE=$3

if [ "$SEVERITY" = "CRITICAL" ] || [ "$SEVERITY" = "HIGH" ]; then
    echo "VulcanGuard Alert: $MESSAGE" | \
    mail -s "[$SEVERITY] VulcanGuard Alert" admin@example.com
fi
EOF

chmod +x /usr/local/bin/vulcan-alert.sh
```

#### Slack Integration
```bash
# Slack webhook alert
cat > /usr/local/bin/vulcan-slack-alert.sh << 'EOF'
#!/bin/bash
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
MESSAGE=$1

curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"🛡️ VulcanGuard Alert: '$MESSAGE'"}' \
    $WEBHOOK_URL
EOF
```

---

## API Reference

### Core API Endpoints

#### Health and Status
```bash
# System health
GET /health
Response: {"status": "healthy", "node_id": "...", "uptime": 3600}

# Detailed status
GET /status
Response: {
  "system": {...},
  "behavioral_profiler": {...},
  "traffic_analyzer": {...},
  "p2p_network": {...}
}

# Metrics
GET /metrics
Response: {"requests_total": 1000, "blocked": 50, ...}
```

#### Configuration Management
```bash
# Get current configuration
GET /api/config

# Update rate limiting
POST /api/config/rate-limit
Body: {"max_requests": 30, "tracking_duration": "30s"}

# Update behavioral profiler settings
POST /api/config/behavioral-profiler
Body: {"similarity_threshold": 0.90, "max_profile_age": "48h"}
```

#### Blacklist Management
```bash
# Get blacklisted IPs
GET /api/blacklist

# Add IP to blacklist
POST /api/blacklist
Body: {"ip": "192.168.1.100", "reason": "manual", "duration": "24h"}

# Remove IP from blacklist
DELETE /api/blacklist/192.168.1.100

# Check if IP is blacklisted
GET /api/blacklist/192.168.1.100
```

#### Behavioral Profiles
```bash
# Get all profiles
GET /api/profiles

# Get specific profile
GET /api/profiles/192.168.1.100

# Get profiles by similarity
GET /api/profiles/similar?ip=192.168.1.100&threshold=0.8

# Update profile manually
POST /api/profiles/192.168.1.100/attack-event
Body: {"type": "ddos", "severity": "high", "description": "Manual report"}
```

#### Traffic Analysis
```bash
# Get global traffic stats
GET /api/traffic/global

# Get endpoint statistics
GET /api/traffic/endpoints

# Get traffic by IP
GET /api/traffic/ips

# Get recent alerts
GET /api/traffic/alerts?since=2025-07-01T00:00:00Z
```

### P2P Network API

```bash
# P2P health
GET :9001/p2p/health

# Peer management
GET :9001/p2p/peers
POST :9001/p2p/peers
Body: {"id": "peer1", "address": "10.0.0.2", "port": "9001"}

# Threat intelligence sync
GET :9001/p2p/sync?since=2025-07-01T00:00:00Z

# Manual threat intelligence sharing
POST :9001/p2p/threat-intel
Body: {
  "type": "blacklist",
  "ip_addresses": ["192.168.1.100"],
  "severity": "high",
  "confidence": 0.95
}
```

---

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors
```bash
# Problem: eBPF/XDP requires root privileges
Error: "failed to load eBPF program: operation not permitted"

# Solution:
sudo ./vulcanguard-enhanced
# Or add CAP_SYS_ADMIN capability
sudo setcap cap_sys_admin+ep vulcanguard-enhanced
```

#### 2. Port Already in Use
```bash
# Problem: Port 8080 or 9001 already in use
Error: "bind: address already in use"

# Solution: Find and kill process
sudo netstat -tulpn | grep :8080
sudo kill -9 <PID>

# Or use different ports
./vulcanguard-enhanced --port 8081 --p2p-port 9002
```

#### 3. BPF Filesystem Not Mounted
```bash
# Problem: XDP features not working
Error: "no such file or directory: /sys/fs/bpf"

# Solution:
sudo mount -t bpf bpf /sys/fs/bpf
echo 'bpf /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab
```

#### 4. P2P Connection Issues
```bash
# Problem: Peers not connecting
Error: "failed to connect to peer"

# Diagnosis:
curl http://peer-ip:9001/p2p/health
telnet peer-ip 9001

# Solutions:
# Check firewall rules
sudo ufw allow 9001
# Check network connectivity
ping peer-ip
# Verify peer configuration
```

#### 5. High Memory Usage
```bash
# Problem: Memory consumption growing
# Check current usage
ps aux | grep vulcanguard

# Solutions:
# Reduce cache sizes in config
behavioral_profiler:
  max_profiles: 5000
traffic_analyzer:
  max_patterns: 1000
p2p_network:
  cache_size: 1000

# Enable memory limits
ulimit -m 1048576  # 1GB limit
```

### Debug Mode

#### Enable Debug Logging
```bash
# Set debug level
export VULCAN_LOG_LEVEL=debug
sudo -E ./vulcanguard-enhanced

# Or via config file
logging:
  level: debug
```

#### Component-Specific Debugging
```bash
# Debug behavioral profiler
curl -X POST http://localhost:8080/api/debug/behavioral-profiler \
  -d '{"enable": true, "level": "trace"}'

# Debug traffic analyzer  
curl -X POST http://localhost:8080/api/debug/traffic-analyzer \
  -d '{"enable": true, "level": "trace"}'

# Debug P2P network
curl -X POST http://localhost:9001/p2p/debug \
  -d '{"enable": true, "level": "trace"}'
```

### Performance Profiling

#### CPU Profiling
```bash
# Enable CPU profiling
./vulcanguard-enhanced --cpuprofile cpu.prof

# Analyze with pprof
go tool pprof cpu.prof
(pprof) top10
(pprof) web
```

#### Memory Profiling
```bash
# Enable memory profiling
./vulcanguard-enhanced --memprofile mem.prof

# Analyze memory usage
go tool pprof mem.prof
(pprof) top10
(pprof) list main.handleRequest
```

---

## Performance Tuning

### System-Level Optimizations

#### Network Tuning
```bash
# Increase network buffer sizes
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' >> /etc/sysctl.conf

# Apply changes
sudo sysctl -p
```

#### File Descriptor Limits
```bash
# Increase file descriptor limits
echo 'fs.file-max = 100000' >> /etc/sysctl.conf
echo '* soft nofile 65536' >> /etc/security/limits.conf
echo '* hard nofile 65536' >> /etc/security/limits.conf

# For systemd service
[Service]
LimitNOFILE=65536
```

### Application-Level Optimizations

#### Memory Optimization
```yaml
# config.yaml - Optimize for memory
behavioral_profiler:
  max_profile_age: 12h      # Reduce from 24h
  cleanup_interval: 30m     # More frequent cleanup
  analysis_queue_size: 500  # Reduce queue size

traffic_analyzer:
  pattern_cache_size: 1000  # Limit pattern cache
  endpoint_cache_size: 500  # Limit endpoint cache

p2p_network:
  cache_size: 2000         # Limit threat intelligence cache
  sync_batch_size: 100     # Smaller sync batches
```

#### CPU Optimization
```yaml
# config.yaml - Optimize for CPU
behavioral_profiler:
  analysis_workers: 4       # Match CPU cores
  batch_size: 50           # Process in batches

traffic_analyzer:
  analysis_interval: 10s   # Less frequent analysis
  pattern_workers: 2       # Dedicated pattern analysis

identity_analyzer:
  similarity_workers: 2    # Parallel similarity analysis
  analysis_batch_size: 20  # Batch processing
```

#### Network Optimization
```yaml
# config.yaml - Optimize for network
p2p_network:
  sync_interval: 10m       # Less frequent syncing
  compression: true        # Enable compression
  batch_intelligence: true # Batch threat intelligence
  connection_pool_size: 10 # Reuse connections

server:
  read_timeout: 10s        # Faster timeouts
  write_timeout: 10s
  idle_timeout: 60s
  keep_alive: true         # Enable keep-alive
```

### Scaling Recommendations

#### Small Deployment (< 1000 req/sec)
```yaml
rate_limiting:
  max_requests: 50
behavioral_profiler:
  max_profiles: 5000
traffic_analyzer:
  analysis_interval: 30s
p2p_network:
  cache_size: 1000
```

#### Medium Deployment (1000-10000 req/sec)  
```yaml
rate_limiting:
  max_requests: 100
behavioral_profiler:
  max_profiles: 20000
  analysis_workers: 8
traffic_analyzer:
  analysis_interval: 15s
  pattern_workers: 4
p2p_network:
  cache_size: 5000
  sync_batch_size: 500
```

#### Large Deployment (> 10000 req/sec)
```yaml
rate_limiting:
  max_requests: 200
behavioral_profiler:
  max_profiles: 100000
  analysis_workers: 16
  batch_size: 100
traffic_analyzer:
  analysis_interval: 5s
  pattern_workers: 8
p2p_network:
  cache_size: 20000
  sync_batch_size: 1000
  compression: true
```

---

## Security Best Practices

### Network Security

#### Firewall Configuration
```bash
# UFW rules for VulcanGuard
sudo ufw allow 8080/tcp    # Main service
sudo ufw allow 9001/tcp    # P2P network
sudo ufw deny 22/tcp from any to any  # Restrict SSH

# Specific peer access only
sudo ufw allow from 10.0.0.0/24 to any port 9001
```

#### TLS/SSL Setup
```yaml
# config.yaml - Enable HTTPS
server:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/vulcanguard.crt"
    key_file: "/etc/ssl/private/vulcanguard.key"

p2p_network:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/vulcanguard-p2p.crt"
    key_file: "/etc/ssl/private/vulcanguard-p2p.key"
    verify_peers: true
```

### Access Control

#### API Authentication
```yaml
# config.yaml - Enable API auth
api:
  authentication:
    enabled: true
    type: "bearer_token"
    tokens:
      - "your-secret-token-here"
  authorization:
    admin_endpoints:
      - "/api/config/*"
      - "/api/blacklist/*"
    readonly_endpoints:
      - "/api/status"
      - "/metrics"
```

#### P2P Network Security
```yaml
# config.yaml - Secure P2P
p2p_network:
  security:
    require_authentication: true
    allowed_peers:
      - "trusted-peer-1"
      - "trusted-peer-2"
    threat_intel_verification: true
    max_peer_connections: 10
```

### Operational Security

#### Log Security
```bash
# Secure log files
sudo chown root:adm /var/log/vulcanguard/
sudo chmod 640 /var/log/vulcanguard/*.log

# Log rotation with compression
# /etc/logrotate.d/vulcanguard
/var/log/vulcanguard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
```

#### Configuration Security
```bash
# Secure configuration files
sudo chown root:root config.yaml
sudo chmod 600 config.yaml

# Use environment variables for secrets
export VULCAN_API_TOKEN="$(openssl rand -hex 32)"
export VULCAN_P2P_SECRET="$(openssl rand -hex 32)"
```

#### Regular Security Updates
```bash
# Create update script
cat > /usr/local/bin/vulcan-update.sh << 'EOF'
#!/bin/bash
cd /home/aditya-sal/Desktop/SystemBackend/VulcanGuard
git pull origin main
./build_enhanced.sh
sudo systemctl restart vulcanguard
EOF

# Schedule weekly updates
echo "0 2 * * 0 /usr/local/bin/vulcan-update.sh" | sudo crontab -
```

---

## Advanced Use Cases

### 1. Multi-Cloud Deployment

#### AWS Setup
```bash
# VulcanGuard on AWS EC2
# Security Group rules
aws ec2 authorize-security-group-ingress \
    --group-id sg-12345678 \
    --protocol tcp \
    --port 8080 \
    --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
    --group-id sg-12345678 \
    --protocol tcp \
    --port 9001 \
    --source-group sg-12345678
```

#### Docker Deployment
```dockerfile
# Dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN ./build_enhanced.sh

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/vulcanguard-enhanced .
EXPOSE 8080 9001
CMD ["./vulcanguard-enhanced"]
```

```bash
# Build and run container
docker build -t vulcanguard-enhanced .
docker run -d \
    --name vulcanguard \
    --cap-add=SYS_ADMIN \
    --network=host \
    -v /var/log/vulcanguard:/var/log/vulcanguard \
    vulcanguard-enhanced
```

### 2. Integration with CDN

#### Cloudflare Integration
```yaml
# config.yaml - Behind Cloudflare
server:
  trusted_proxies:
    - "173.245.48.0/20"
    - "103.21.244.0/22"
    - "103.22.200.0/22"
  real_ip_header: "CF-Connecting-IP"

behavioral_profiler:
  extract_real_ip: true
  cloudflare_mode: true
```

### 3. Custom Attack Detection

#### Custom Rules Engine
```yaml
# config.yaml - Custom rules
custom_rules:
  - name: "API Abuse Detection"
    pattern: "POST /api/.*"
    threshold: 100
    window: "1m"
    action: "block"
    
  - name: "Scraping Detection"
    pattern: "GET /.*\\.(jpg|png|pdf)"
    threshold: 50
    window: "5m"
    action: "rate_limit"
```

---

This comprehensive usage guide covers everything from basic setup to advanced enterprise deployments. The VulcanGuard Enhanced system is now ready for production use with robust DDoS protection, behavioral analysis, and distributed threat intelligence capabilities.

For additional support or questions, refer to the [ENHANCED_FEATURES.md](ENHANCED_FEATURES.md) documentation or check the troubleshooting section above.
