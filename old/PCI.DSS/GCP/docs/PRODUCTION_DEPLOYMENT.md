# GCP PCI DSS Framework Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the complete GCP PCI DSS shared library framework in production environments, covering security considerations, performance optimization, monitoring, and operational procedures.

## Pre-Deployment Checklist

### Environment Requirements

#### System Requirements
- [ ] **Operating System**: Linux/Unix with Bash 4.0+
- [ ] **Memory**: Minimum 4GB RAM (8GB+ recommended for organization assessments)
- [ ] **CPU**: 2+ cores (4+ cores recommended for large-scale assessments)
- [ ] **Disk Space**: 10GB+ available space for reports and temporary files
- [ ] **Network**: Reliable internet connectivity to GCP APIs

#### Software Dependencies
- [ ] **Google Cloud SDK**: Latest version installed and configured
- [ ] **jq**: JSON processor for data manipulation
- [ ] **curl**: HTTP client for API connectivity testing
- [ ] **bc**: Calculator for performance calculations (optional)

#### GCP Prerequisites
- [ ] **Authentication**: Service account or user authentication configured
- [ ] **IAM Permissions**: Appropriate permissions for assessment scope
- [ ] **API Access**: Required GCP APIs enabled
- [ ] **Quotas**: Sufficient API quotas for assessment volume

### Security Validation

#### Framework Security
- [ ] **File Permissions**: Libraries have appropriate permissions (644)
- [ ] **Directory Permissions**: Framework directories secured (755)
- [ ] **Code Review**: Security review of any customizations
- [ ] **Audit Logging**: Audit logging configured where required

#### GCP Security
- [ ] **Service Account Security**: Minimal required permissions only
- [ ] **Key Management**: Secure storage of service account keys
- [ ] **Network Security**: Secure network configuration for API access
- [ ] **Access Controls**: Proper RBAC for framework users

## Deployment Architecture

### Deployment Models

#### Model 1: Single-Instance Deployment
**Use Case**: Small organizations (1-50 projects)
**Architecture**: Single server with complete framework
**Scalability**: Vertical scaling only
**Complexity**: Low

```
┌─────────────────────┐
│   Assessment Host   │
│                     │
│  ┌───────────────┐  │
│  │ GCP Framework │  │
│  │ (4 Libraries) │  │
│  └───────────────┘  │
│                     │
│  ┌───────────────┐  │
│  │ Report Storage│  │
│  └───────────────┘  │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│      GCP APIs       │
└─────────────────────┘
```

#### Model 2: Multi-Instance Deployment
**Use Case**: Medium to large organizations (50-200 projects)
**Architecture**: Multiple assessment nodes with shared storage
**Scalability**: Horizontal scaling
**Complexity**: Medium

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│Assessment   │  │Assessment   │  │Assessment   │
│   Node 1    │  │   Node 2    │  │   Node N    │
└─────────────┘  └─────────────┘  └─────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                    ┌─────────────┐
                    │   Shared    │
                    │   Storage   │
                    └─────────────┘
                         │
                         ▼
                ┌─────────────────────┐
                │      GCP APIs       │
                └─────────────────────┘
```

#### Model 3: Enterprise Deployment
**Use Case**: Large enterprises (200+ projects)
**Architecture**: Orchestrated deployment with load balancing
**Scalability**: Auto-scaling
**Complexity**: High

```
┌─────────────────────┐
│   Load Balancer     │
└─────────────────────┘
           │
    ┌──────┴──────┐
    │             │
┌─────────┐  ┌─────────┐
│Assessment│  │Assessment│
│Cluster A │  │Cluster B │
└─────────┘  └─────────┘
    │             │
    └──────┬──────┘
           │
    ┌─────────────┐
    │   Shared    │
    │ Services    │
    │ - Storage   │
    │ - Cache     │
    │ - Queue     │
    └─────────────┘
```

## Installation Procedures

### Standard Installation

#### 1. Framework Download and Setup
```bash
#!/usr/bin/env bash
# Production deployment script

# Configuration
FRAMEWORK_DIR="/opt/gcp-pci-framework"
USER="gcp-assessor"
GROUP="gcp-assessor"

# Create framework user
sudo useradd -r -m -d "$FRAMEWORK_DIR" -s /bin/bash "$USER"
sudo usermod -a -G "$GROUP" "$USER"

# Create directory structure
sudo mkdir -p "$FRAMEWORK_DIR"/{lib,bin,config,logs,reports,tmp}
sudo chown -R "$USER:$GROUP" "$FRAMEWORK_DIR"
sudo chmod 755 "$FRAMEWORK_DIR"

# Install framework libraries
sudo -u "$USER" cp lib/*.sh "$FRAMEWORK_DIR/lib/"
sudo -u "$USER" chmod 644 "$FRAMEWORK_DIR/lib/"*.sh

# Install assessment scripts
sudo -u "$USER" cp check_gcp_pci_requirement*.sh "$FRAMEWORK_DIR/bin/"
sudo -u "$USER" chmod 755 "$FRAMEWORK_DIR/bin/"*.sh

# Create configuration files
sudo -u "$USER" tee "$FRAMEWORK_DIR/config/framework.conf" << EOF
# GCP PCI DSS Framework Configuration
FRAMEWORK_HOME="$FRAMEWORK_DIR"
LOG_LEVEL="INFO"
ENABLE_DEBUG=false
CACHE_ENABLED=true
CACHE_TIMEOUT=3600
MAX_PARALLEL_PROJECTS=5
REPORT_RETENTION_DAYS=90
EOF
```

#### 2. Environment Configuration
```bash
# Setup environment for framework user
sudo -u "$USER" tee "$FRAMEWORK_DIR/.bashrc" << 'EOF'
# GCP PCI DSS Framework Environment
export FRAMEWORK_HOME="/opt/gcp-pci-framework"
export PATH="$FRAMEWORK_HOME/bin:$PATH"
export LD_LIBRARY_PATH="$FRAMEWORK_HOME/lib:$LD_LIBRARY_PATH"

# GCP Configuration
export CLOUDSDK_CORE_DISABLE_PROMPTS=1
export CLOUDSDK_CORE_REQUEST_TIMEOUT=300

# Framework Configuration
source "$FRAMEWORK_HOME/config/framework.conf"

# Logging
export LOG_DIR="$FRAMEWORK_HOME/logs"
export LOG_FILE="$LOG_DIR/framework_$(date +%Y%m%d).log"

# Aliases
alias gcp-assess='cd $FRAMEWORK_HOME/bin'
alias gcp-logs='tail -f $LOG_FILE'
alias gcp-reports='cd $FRAMEWORK_HOME/reports'
EOF
```

#### 3. GCP Authentication Setup
```bash
# Service Account Authentication (Recommended for Production)
SERVICE_ACCOUNT_KEY="$FRAMEWORK_DIR/config/service-account.json"

# Secure service account key
sudo -u "$USER" tee "$SERVICE_ACCOUNT_KEY" << 'EOF'
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "pci-assessor@your-project-id.iam.gserviceaccount.com",
  "client_id": "client-id",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
EOF

sudo chmod 600 "$SERVICE_ACCOUNT_KEY"

# Activate service account
sudo -u "$USER" gcloud auth activate-service-account \
    --key-file="$SERVICE_ACCOUNT_KEY"

# Set default project
sudo -u "$USER" gcloud config set project "your-project-id"
```

### Containerized Deployment

#### Dockerfile
```dockerfile
FROM google/cloud-sdk:alpine

# Install additional dependencies
RUN apk add --no-cache \
    bash \
    jq \
    curl \
    bc \
    && rm -rf /var/cache/apk/*

# Create framework user
RUN adduser -D -s /bin/bash gcp-assessor

# Set working directory
WORKDIR /opt/gcp-pci-framework

# Copy framework files
COPY lib/ ./lib/
COPY bin/ ./bin/
COPY config/ ./config/

# Set permissions
RUN chown -R gcp-assessor:gcp-assessor /opt/gcp-pci-framework && \
    chmod 755 /opt/gcp-pci-framework && \
    chmod 644 ./lib/*.sh && \
    chmod 755 ./bin/*.sh

# Switch to framework user
USER gcp-assessor

# Set environment
ENV FRAMEWORK_HOME=/opt/gcp-pci-framework
ENV PATH="$FRAMEWORK_HOME/bin:$PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD gcloud auth list --filter=status:ACTIVE --format="value(account)" || exit 1

# Default command
CMD ["/bin/bash"]
```

#### Docker Compose Configuration
```yaml
version: '3.8'

services:
  gcp-pci-assessor:
    build: .
    container_name: gcp-pci-framework
    environment:
      - GOOGLE_APPLICATION_CREDENTIALS=/opt/gcp-pci-framework/config/service-account.json
      - CLOUDSDK_CORE_DISABLE_PROMPTS=1
    volumes:
      - ./config/service-account.json:/opt/gcp-pci-framework/config/service-account.json:ro
      - ./reports:/opt/gcp-pci-framework/reports
      - ./logs:/opt/gcp-pci-framework/logs
    networks:
      - gcp-network
    restart: unless-stopped

  report-server:
    image: nginx:alpine
    container_name: report-server
    ports:
      - "8080:80"
    volumes:
      - ./reports:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    networks:
      - gcp-network
    depends_on:
      - gcp-pci-assessor

networks:
  gcp-network:
    driver: bridge
```

## Configuration Management

### Framework Configuration

#### Configuration File Structure
```bash
# /opt/gcp-pci-framework/config/framework.conf

# Core Configuration
FRAMEWORK_VERSION="2.0"
FRAMEWORK_HOME="/opt/gcp-pci-framework"
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
ENABLE_DEBUG=false

# Performance Configuration
MAX_PARALLEL_PROJECTS=5
API_RATE_LIMIT_DELAY=0.1
MEMORY_LIMIT_MB=1024
DISK_SPACE_THRESHOLD_GB=5

# Caching Configuration
CACHE_ENABLED=true
CACHE_DIR="$FRAMEWORK_HOME/tmp/cache"
CACHE_TIMEOUT=3600  # 1 hour
PROJECTS_CACHE_TIMEOUT=7200  # 2 hours

# Report Configuration
REPORT_STORAGE_DIR="$FRAMEWORK_HOME/reports"
REPORT_RETENTION_DAYS=90
REPORT_COMPRESSION=true
REPORT_FORMAT="html"  # html, json, both

# Security Configuration
SECURE_TEMP_FILES=true
LOG_SENSITIVE_DATA=false
AUDIT_LOGGING=true
AUDIT_LOG_FILE="$FRAMEWORK_HOME/logs/audit.log"

# Network Configuration
HTTP_TIMEOUT=300
MAX_RETRIES=3
RETRY_BACKOFF=2
```

#### Environment-Specific Configurations

**Development Environment**
```bash
# config/dev.conf
LOG_LEVEL="DEBUG"
ENABLE_DEBUG=true
MAX_PARALLEL_PROJECTS=2
CACHE_TIMEOUT=300
REPORT_RETENTION_DAYS=7
```

**Production Environment**
```bash
# config/prod.conf
LOG_LEVEL="INFO"
ENABLE_DEBUG=false
MAX_PARALLEL_PROJECTS=10
CACHE_TIMEOUT=7200
REPORT_RETENTION_DAYS=365
AUDIT_LOGGING=true
```

### Service Configuration

#### Systemd Service File
```ini
# /etc/systemd/system/gcp-pci-framework.service

[Unit]
Description=GCP PCI DSS Assessment Framework
After=network.target
Wants=network.target

[Service]
Type=simple
User=gcp-assessor
Group=gcp-assessor
WorkingDirectory=/opt/gcp-pci-framework
Environment=FRAMEWORK_HOME=/opt/gcp-pci-framework
Environment=GOOGLE_APPLICATION_CREDENTIALS=/opt/gcp-pci-framework/config/service-account.json
ExecStart=/opt/gcp-pci-framework/bin/framework-daemon.sh
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### Framework Daemon Script
```bash
#!/usr/bin/env bash
# /opt/gcp-pci-framework/bin/framework-daemon.sh

# Load framework configuration
source "$FRAMEWORK_HOME/config/framework.conf"

# Setup logging
exec 1> >(logger -t gcp-pci-framework)
exec 2> >(logger -t gcp-pci-framework)

# Main daemon loop
while true; do
    # Check for scheduled assessments
    if [[ -f "$FRAMEWORK_HOME/config/scheduled-assessments.conf" ]]; then
        source "$FRAMEWORK_HOME/config/scheduled-assessments.conf"
        
        # Process scheduled assessments
        process_scheduled_assessments
    fi
    
    # Cleanup old reports
    cleanup_old_reports
    
    # Health check
    perform_health_check
    
    # Sleep until next check
    sleep 300  # 5 minutes
done
```

## Security Hardening

### File System Security

#### Directory Permissions
```bash
# Secure framework directories
chmod 755 /opt/gcp-pci-framework
chmod 755 /opt/gcp-pci-framework/{bin,lib,reports,logs}
chmod 750 /opt/gcp-pci-framework/{config,tmp}

# Secure configuration files
chmod 644 /opt/gcp-pci-framework/config/framework.conf
chmod 600 /opt/gcp-pci-framework/config/service-account.json
chmod 640 /opt/gcp-pci-framework/config/*-secrets.conf

# Secure log files
chmod 640 /opt/gcp-pci-framework/logs/*.log
```

#### SELinux Configuration (if applicable)
```bash
# Set SELinux contexts
semanage fcontext -a -t bin_t "/opt/gcp-pci-framework/bin(/.*)?"
semanage fcontext -a -t lib_t "/opt/gcp-pci-framework/lib(/.*)?"
semanage fcontext -a -t admin_home_t "/opt/gcp-pci-framework/config(/.*)?"
semanage fcontext -a -t var_log_t "/opt/gcp-pci-framework/logs(/.*)?"

# Apply contexts
restorecon -R /opt/gcp-pci-framework
```

### Network Security

#### Firewall Configuration
```bash
# Allow outbound HTTPS to GCP APIs
iptables -A OUTPUT -p tcp --dport 443 -d googleapis.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d accounts.google.com -j ACCEPT

# Block all other outbound traffic (optional, depending on requirements)
iptables -A OUTPUT -j DROP

# Allow inbound SSH for management (restrict to management networks)
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
```

#### SSL/TLS Configuration
```bash
# Ensure strong TLS configuration for gcloud
gcloud config set core/custom_ca_certs_file /path/to/ca-certificates.crt
gcloud config set core/disable_ssl_validation false
```

### Access Controls

#### RBAC Configuration
```bash
# Create role-based access groups
groupadd gcp-pci-admins
groupadd gcp-pci-assessors
groupadd gcp-pci-viewers

# Configure sudo access
echo "%gcp-pci-admins ALL=(gcp-assessor) ALL" >> /etc/sudoers.d/gcp-pci-framework
echo "%gcp-pci-assessors ALL=(gcp-assessor) NOPASSWD: /opt/gcp-pci-framework/bin/check_gcp_pci_requirement*.sh" >> /etc/sudoers.d/gcp-pci-framework
```

## Monitoring and Logging

### Application Logging

#### Log Configuration
```bash
# /opt/gcp-pci-framework/config/logging.conf

# Log Levels: DEBUG, INFO, WARN, ERROR
DEFAULT_LOG_LEVEL="INFO"

# Log Destinations
CONSOLE_LOGGING=true
FILE_LOGGING=true
SYSLOG_LOGGING=true

# Log Files
FRAMEWORK_LOG="$FRAMEWORK_HOME/logs/framework.log"
ASSESSMENT_LOG="$FRAMEWORK_HOME/logs/assessment.log"
ERROR_LOG="$FRAMEWORK_HOME/logs/error.log"
AUDIT_LOG="$FRAMEWORK_HOME/logs/audit.log"

# Log Rotation
LOG_MAX_SIZE="100M"
LOG_KEEP_DAYS=30
LOG_COMPRESS=true
```

#### Logrotate Configuration
```bash
# /etc/logrotate.d/gcp-pci-framework

/opt/gcp-pci-framework/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 gcp-assessor gcp-assessor
    postrotate
        systemctl reload gcp-pci-framework
    endscript
}
```

### System Monitoring

#### Health Check Script
```bash
#!/usr/bin/env bash
# /opt/gcp-pci-framework/bin/health-check.sh

# Framework health check
check_framework_health() {
    local status=0
    
    # Check framework libraries
    for lib in gcp_common.sh gcp_permissions.sh gcp_html_report.sh gcp_scope_mgmt.sh; do
        if [[ ! -f "$FRAMEWORK_HOME/lib/$lib" ]]; then
            echo "ERROR: Missing library: $lib"
            status=1
        fi
    done
    
    # Check GCP authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" >/dev/null 2>&1; then
        echo "ERROR: GCP authentication not active"
        status=1
    fi
    
    # Check disk space
    local disk_usage=$(df "$FRAMEWORK_HOME" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 90 ]]; then
        echo "WARNING: Disk usage at ${disk_usage}%"
        status=2
    fi
    
    # Check memory usage
    local memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ $memory_usage -gt 90 ]]; then
        echo "WARNING: Memory usage at ${memory_usage}%"
        status=2
    fi
    
    return $status
}

# Run health check
check_framework_health
exit $?
```

#### Monitoring Integration
```bash
# Nagios/Icinga check
define command {
    command_name    check_gcp_pci_framework
    command_line    /opt/gcp-pci-framework/bin/health-check.sh
}

# Prometheus metrics endpoint
create_prometheus_metrics() {
    cat > /opt/gcp-pci-framework/logs/metrics.prom << EOF
# HELP gcp_pci_framework_assessments_total Total number of assessments performed
# TYPE gcp_pci_framework_assessments_total counter
gcp_pci_framework_assessments_total $(grep "Assessment completed" "$FRAMEWORK_LOG" | wc -l)

# HELP gcp_pci_framework_errors_total Total number of errors
# TYPE gcp_pci_framework_errors_total counter
gcp_pci_framework_errors_total $(grep "ERROR" "$ERROR_LOG" | wc -l)

# HELP gcp_pci_framework_disk_usage_percent Disk usage percentage
# TYPE gcp_pci_framework_disk_usage_percent gauge
gcp_pci_framework_disk_usage_percent $(df "$FRAMEWORK_HOME" | awk 'NR==2 {print $5}' | sed 's/%//')
EOF
}
```

## Backup and Recovery

### Backup Strategy

#### Backup Script
```bash
#!/usr/bin/env bash
# /opt/gcp-pci-framework/bin/backup-framework.sh

BACKUP_DIR="/backup/gcp-pci-framework"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/framework_backup_$TIMESTAMP.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
tar -czf "$BACKUP_FILE" \
    -C /opt \
    --exclude="gcp-pci-framework/tmp/*" \
    --exclude="gcp-pci-framework/logs/*.log" \
    gcp-pci-framework/

# Verify backup
if [[ -f "$BACKUP_FILE" ]]; then
    echo "Backup created: $BACKUP_FILE"
    
    # Test backup integrity
    if tar -tzf "$BACKUP_FILE" >/dev/null 2>&1; then
        echo "Backup integrity verified"
    else
        echo "ERROR: Backup integrity check failed"
        exit 1
    fi
else
    echo "ERROR: Backup creation failed"
    exit 1
fi

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "framework_backup_*.tar.gz" -mtime +30 -delete
```

### Recovery Procedures

#### Recovery Script
```bash
#!/usr/bin/env bash
# /opt/gcp-pci-framework/bin/restore-framework.sh

BACKUP_FILE="$1"

if [[ -z "$BACKUP_FILE" ]]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop framework service
systemctl stop gcp-pci-framework

# Backup current installation
mv /opt/gcp-pci-framework /opt/gcp-pci-framework.backup.$(date +%Y%m%d_%H%M%S)

# Restore from backup
tar -xzf "$BACKUP_FILE" -C /opt

# Restore permissions
chown -R gcp-assessor:gcp-assessor /opt/gcp-pci-framework
chmod -R 755 /opt/gcp-pci-framework
chmod 750 /opt/gcp-pci-framework/config
chmod 600 /opt/gcp-pci-framework/config/service-account.json

# Start framework service
systemctl start gcp-pci-framework

# Verify restoration
if systemctl is-active gcp-pci-framework >/dev/null 2>&1; then
    echo "Framework restored and running successfully"
else
    echo "ERROR: Framework restoration failed"
    exit 1
fi
```

## Operational Procedures

### Maintenance Tasks

#### Routine Maintenance Script
```bash
#!/usr/bin/env bash
# /opt/gcp-pci-framework/bin/maintenance.sh

# Daily maintenance tasks
perform_daily_maintenance() {
    echo "Performing daily maintenance..."
    
    # Cleanup old temporary files
    find "$FRAMEWORK_HOME/tmp" -type f -mtime +1 -delete
    
    # Cleanup old cache files
    find "$FRAMEWORK_HOME/tmp/cache" -type f -mtime +1 -delete
    
    # Rotate large log files
    for log_file in "$FRAMEWORK_HOME/logs"/*.log; do
        if [[ $(stat -c%s "$log_file" 2>/dev/null) -gt 104857600 ]]; then  # >100MB
            logrotate -f /etc/logrotate.d/gcp-pci-framework
        fi
    done
    
    # Update framework libraries (if auto-update enabled)
    if [[ "$AUTO_UPDATE" == "true" ]]; then
        update_framework_libraries
    fi
}

# Weekly maintenance tasks
perform_weekly_maintenance() {
    echo "Performing weekly maintenance..."
    
    # Archive old reports
    find "$FRAMEWORK_HOME/reports" -name "*.html" -mtime +7 -exec gzip {} \;
    
    # Cleanup archived reports older than retention period
    find "$FRAMEWORK_HOME/reports" -name "*.gz" -mtime +$REPORT_RETENTION_DAYS -delete
    
    # Performance analysis
    analyze_performance_metrics
    
    # Security audit
    perform_security_audit
}

# Performance analysis
analyze_performance_metrics() {
    echo "Analyzing performance metrics..."
    
    # Generate performance report
    cat > "$FRAMEWORK_HOME/reports/performance_$(date +%Y%m%d).txt" << EOF
Performance Report - $(date)

Framework Loading Times:
$(grep "Framework loaded" "$FRAMEWORK_HOME/logs/framework.log" | tail -100 | awk '{print $NF}' | sort -n | awk '{sum+=$1} END {print "Average: " sum/NR "s"}')

Assessment Execution Times:
$(grep "Assessment completed" "$FRAMEWORK_HOME/logs/assessment.log" | tail -100 | awk '{print $NF}' | sort -n | awk '{sum+=$1} END {print "Average: " sum/NR "s"}')

Error Rate:
$(echo "scale=2; $(grep "ERROR" "$FRAMEWORK_HOME/logs/error.log" | wc -l) / $(grep "Assessment" "$FRAMEWORK_HOME/logs/assessment.log" | wc -l) * 100" | bc)%

EOF
}
```

### Update Procedures

#### Framework Update Script
```bash
#!/usr/bin/env bash
# /opt/gcp-pci-framework/bin/update-framework.sh

NEW_VERSION="$1"
UPDATE_SOURCE="$2"

if [[ -z "$NEW_VERSION" ]]; then
    echo "Usage: $0 <version> [source_path]"
    exit 1
fi

# Backup current version
backup_current_version() {
    local backup_dir="/opt/gcp-pci-framework-backups"
    local current_version=$(cat "$FRAMEWORK_HOME/VERSION" 2>/dev/null || echo "unknown")
    
    mkdir -p "$backup_dir"
    tar -czf "$backup_dir/framework_${current_version}_$(date +%Y%m%d_%H%M%S).tar.gz" \
        -C /opt gcp-pci-framework
}

# Update framework
update_framework() {
    echo "Updating framework to version $NEW_VERSION..."
    
    # Stop framework service
    systemctl stop gcp-pci-framework
    
    # Backup current version
    backup_current_version
    
    # Update libraries
    if [[ -n "$UPDATE_SOURCE" ]]; then
        cp "$UPDATE_SOURCE"/lib/*.sh "$FRAMEWORK_HOME/lib/"
        cp "$UPDATE_SOURCE"/bin/*.sh "$FRAMEWORK_HOME/bin/"
    fi
    
    # Update version file
    echo "$NEW_VERSION" > "$FRAMEWORK_HOME/VERSION"
    
    # Verify update
    if verify_framework_integrity; then
        systemctl start gcp-pci-framework
        echo "Framework updated successfully to version $NEW_VERSION"
    else
        echo "ERROR: Framework integrity check failed, rolling back..."
        rollback_update
        exit 1
    fi
}

# Verify framework integrity
verify_framework_integrity() {
    local required_files=(
        "lib/gcp_common.sh"
        "lib/gcp_permissions.sh"
        "lib/gcp_html_report.sh"
        "lib/gcp_scope_mgmt.sh"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$FRAMEWORK_HOME/$file" ]]; then
            echo "ERROR: Missing required file: $file"
            return 1
        fi
    done
    
    # Test framework loading
    if ! source "$FRAMEWORK_HOME/lib/gcp_common.sh"; then
        echo "ERROR: Failed to load gcp_common.sh"
        return 1
    fi
    
    return 0
}

update_framework
```

## Disaster Recovery

### Disaster Recovery Plan

#### Recovery Time Objectives (RTO)
- **Critical Systems**: 4 hours
- **Standard Systems**: 24 hours
- **Development Systems**: 72 hours

#### Recovery Point Objectives (RPO)
- **Configuration Data**: 0 hours (real-time backup)
- **Assessment Reports**: 24 hours
- **Log Data**: 24 hours

#### Recovery Procedures

1. **System Failure Recovery**
   - Assess damage and determine recovery approach
   - Restore from latest system backup
   - Restore framework from backup
   - Verify functionality and resume operations

2. **Data Center Failure Recovery**
   - Activate secondary site
   - Restore latest backups to new environment
   - Update DNS and network configurations
   - Resume operations

3. **Framework Corruption Recovery**
   - Stop framework services
   - Restore from known good backup
   - Verify integrity and update if necessary
   - Resume normal operations

## Compliance and Auditing

### Audit Requirements

#### PCI DSS Compliance
- **Requirement 10**: Log all access to cardholder data
- **Requirement 11**: Regular security testing
- **Requirement 12**: Information security policy

#### Audit Logging Configuration
```bash
# Enable comprehensive audit logging
AUDIT_EVENTS=(
    "framework_start"
    "framework_stop"
    "assessment_start"
    "assessment_complete"
    "permission_check"
    "scope_change"
    "report_generation"
    "error_occurrence"
)

# Audit log format
log_audit_event() {
    local event_type="$1"
    local details="$2"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local user=$(whoami)
    
    echo "$timestamp|$user|$event_type|$details" >> "$AUDIT_LOG_FILE"
}
```

### Compliance Reporting

#### Compliance Report Generation
```bash
#!/usr/bin/env bash
# Generate compliance report

generate_compliance_report() {
    local report_file="$FRAMEWORK_HOME/reports/compliance_$(date +%Y%m%d).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GCP PCI DSS Framework Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .pass { color: green; }
        .fail { color: red; }
    </style>
</head>
<body>
    <h1>PCI DSS Framework Compliance Report</h1>
    <p>Generated: $(date)</p>
    
    <h2>Framework Status</h2>
    <table>
        <tr><th>Component</th><th>Status</th><th>Details</th></tr>
        <tr><td>Framework Version</td><td class="pass">Current</td><td>$(cat "$FRAMEWORK_HOME/VERSION")</td></tr>
        <tr><td>Security Updates</td><td class="pass">Up to Date</td><td>Last checked: $(date)</td></tr>
        <tr><td>Audit Logging</td><td class="pass">Enabled</td><td>Logging to: $AUDIT_LOG_FILE</td></tr>
        <tr><td>Access Controls</td><td class="pass">Configured</td><td>RBAC enabled</td></tr>
    </table>
    
    <h2>Assessment Statistics</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Assessments</td><td>$(grep "Assessment completed" "$FRAMEWORK_LOG" | wc -l)</td></tr>
        <tr><td>Success Rate</td><td>$(echo "scale=2; ($(grep "Assessment completed" "$FRAMEWORK_LOG" | wc -l) - $(grep "ERROR" "$ERROR_LOG" | wc -l)) / $(grep "Assessment completed" "$FRAMEWORK_LOG" | wc -l) * 100" | bc)%</td></tr>
        <tr><td>Average Execution Time</td><td>$(grep "Assessment completed" "$FRAMEWORK_LOG" | awk '{print $NF}' | sort -n | awk '{sum+=$1} END {print sum/NR "s"}')</td></tr>
    </table>
</body>
</html>
EOF
    
    echo "Compliance report generated: $report_file"
}
```

## Support and Escalation

### Support Tiers

#### Tier 1: Self-Service
- Documentation review
- Log analysis
- Basic troubleshooting
- Configuration verification

#### Tier 2: Technical Support
- Advanced troubleshooting
- Performance optimization
- Integration assistance
- Custom configuration

#### Tier 3: Expert Support
- Framework modifications
- Security reviews
- Disaster recovery
- Compliance consulting

### Contact Information

#### Internal Support
- **Framework Administrator**: admin@company.com
- **Security Team**: security@company.com
- **DevOps Team**: devops@company.com

#### External Support
- **GCP Support**: Google Cloud Platform support portal
- **PCI DSS Guidance**: PCI Security Standards Council
- **Security Vendors**: Approved security consulting partners