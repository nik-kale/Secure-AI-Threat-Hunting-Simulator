# Deployment Guide

This guide covers deploying the AI Threat Hunting Simulator in various environments, from local development to production deployments.

## Table of Contents

1. [Quick Start (Docker Compose)](#quick-start-docker-compose)
2. [Production Deployment](#production-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Configuration](#configuration)
5. [Monitoring & Observability](#monitoring--observability)
6. [Security Best Practices](#security-best-practices)
7. [Scaling](#scaling)
8. [Troubleshooting](#troubleshooting)

## Quick Start (Docker Compose)

### Prerequisites

- Docker 24.0+ and Docker Compose 2.20+
- 4GB RAM minimum, 8GB recommended
- 10GB disk space

### Steps

1. **Clone and configure:**

```bash
git clone https://github.com/yourusername/ai-threat-hunting-simulator.git
cd ai-threat-hunting-simulator
cp .env.example .env
```

2. **Edit configuration (optional):**

```bash
nano .env
# Configure LLM provider, threat intel API keys, etc.
```

3. **Start all services:**

```bash
docker-compose up --build
```

This starts:
- **Analysis Engine API**: http://localhost:8000
- **SOC Dashboard UI**: http://localhost:3000
- **Database**: PostgreSQL on port 5432 (internal)

4. **Verify health:**

```bash
curl http://localhost:8000/health
curl http://localhost:3000
```

5. **Stop services:**

```bash
docker-compose down
# To also remove volumes:
docker-compose down -v
```

### Docker Compose Services

The `docker-compose.yml` file defines three main services:

```yaml
services:
  analysis-engine:    # FastAPI backend on port 8000
  soc-dashboard:      # React UI on port 3000
  database:           # PostgreSQL database (internal)
```

## Production Deployment

### Environment Variables

For production, configure these in `.env`:

```bash
# API Configuration
ANALYSIS_API_HOST=0.0.0.0
ANALYSIS_API_PORT=8000
API_WORKERS=4  # Adjust based on CPU cores

# Security
API_KEY=<generate-strong-key>
ADMIN_API_KEY=<generate-strong-admin-key>
ALLOWED_ORIGINS=https://yourdomain.com

# Database (use PostgreSQL in production)
DB_CONNECTION_STRING=postgresql://user:password@db:5432/threat_hunting
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40

# LLM Integration (optional)
LLM_PROVIDER=openai
OPENAI_API_KEY=<your-key>

# Threat Intelligence (optional)
ENABLE_THREAT_INTEL=true
ABUSEIPDB_API_KEY=<your-key>
VIRUSTOTAL_API_KEY=<your-key>

# Monitoring
ENABLE_METRICS=true
SENTRY_DSN=<your-sentry-dsn>

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### Using PostgreSQL (Recommended for Production)

1. **Update docker-compose.yml:**

```yaml
services:
  database:
    image: postgres:16
    environment:
      POSTGRES_DB: threat_hunting
      POSTGRES_USER: threat_hunter
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

2. **Update .env:**

```bash
DB_CONNECTION_STRING=postgresql://threat_hunter:${DB_PASSWORD}@database:5432/threat_hunting
```

3. **Initialize database:**

```bash
docker-compose up database
# Database tables are auto-created on first API startup
docker-compose up analysis-engine
```

### Reverse Proxy (Nginx)

For production, use Nginx as a reverse proxy:

**nginx.conf:**

```nginx
upstream api_backend {
    server localhost:8000;
}

upstream ui_frontend {
    server localhost:3000;
}

server {
    listen 80;
    server_name yourdomain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/ssl/certs/yourdomain.com.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.com.key;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # API endpoints
    location /api/ {
        proxy_pass http://api_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for large file uploads
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        client_max_body_size 100M;
    }

    # Frontend UI
    location / {
        proxy_pass http://ui_frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://api_backend/health;
        access_log off;
    }

    # Metrics (restrict to internal IPs)
    location /metrics {
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        proxy_pass http://api_backend/metrics;
    }
}
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.27+
- kubectl configured
- Helm 3.12+ (optional, for easier deployment)

### Kubernetes Manifests

**1. Create namespace:**

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: threat-hunting
```

**2. ConfigMap for environment variables:**

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: threat-hunting
data:
  ANALYSIS_API_PORT: "8000"
  LOG_LEVEL: "INFO"
  LOG_FORMAT: "json"
  CORRELATION_TIME_WINDOW_MINUTES: "60"
  ENABLE_METRICS: "true"
```

**3. Secrets (create separately):**

```bash
kubectl create secret generic app-secrets \
  --from-literal=api-key=<your-api-key> \
  --from-literal=openai-api-key=<your-openai-key> \
  --from-literal=db-password=<your-db-password> \
  -n threat-hunting
```

**4. PostgreSQL deployment:**

```yaml
# postgres-deployment.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: threat-hunting
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: threat-hunting
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:16
        env:
        - name: POSTGRES_DB
          value: threat_hunting
        - name: POSTGRES_USER
          value: threat_hunter
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: db-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: threat-hunting
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

**5. Analysis Engine deployment:**

```yaml
# analysis-engine-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: analysis-engine
  namespace: threat-hunting
spec:
  replicas: 3
  selector:
    matchLabels:
      app: analysis-engine
  template:
    metadata:
      labels:
        app: analysis-engine
    spec:
      containers:
      - name: analysis-engine
        image: your-registry/analysis-engine:latest
        ports:
        - containerPort: 8000
        env:
        - name: ANALYSIS_API_PORT
          value: "8000"
        - name: DB_CONNECTION_STRING
          value: "postgresql://threat_hunter:$(DB_PASSWORD)@postgres:5432/threat_hunting"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: db-password
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: api-key
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: openai-api-key
        envFrom:
        - configMapRef:
            name: app-config
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: analysis-engine
  namespace: threat-hunting
spec:
  selector:
    app: analysis-engine
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: analysis-engine-hpa
  namespace: threat-hunting
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: analysis-engine
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

**6. Ingress:**

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: threat-hunting-ingress
  namespace: threat-hunting
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - yourdomain.com
    secretName: threat-hunting-tls
  rules:
  - host: yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: analysis-engine
            port:
              number: 8000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: soc-dashboard
            port:
              number: 3000
```

**Deploy:**

```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
# Create secrets first (see step 3)
kubectl apply -f postgres-deployment.yaml
kubectl apply -f analysis-engine-deployment.yaml
kubectl apply -f ingress.yaml
```

## Monitoring & Observability

### Prometheus Metrics

The API exposes Prometheus metrics at `/metrics`:

```bash
# Scrape metrics
curl http://localhost:8000/metrics
```

**Prometheus scrape config:**

```yaml
scrape_configs:
  - job_name: 'threat-hunting-api'
    static_configs:
      - targets: ['analysis-engine:8000']
    metrics_path: '/metrics'
```

### Grafana Dashboard

Key metrics to monitor:

- `http_requests_total` - Total HTTP requests by endpoint and status
- `http_request_duration_seconds` - Request latency
- `analysis_requests_total` - Analysis pipeline requests
- `events_processed_total` - Total events processed
- `sessions_detected_total` - Sessions detected
- `current_analysis_jobs` - Current running analyses

### Logging

Structured JSON logs are written to stdout in production mode:

```json
{
  "timestamp": "2025-11-16T12:34:56Z",
  "level": "INFO",
  "logger": "analysis_engine.pipeline",
  "message": "Analysis completed",
  "correlation_id": "abc-123",
  "duration_seconds": 2.5,
  "events_processed": 105
}
```

## Security Best Practices

### 1. API Keys

```bash
# Generate strong API keys
openssl rand -hex 32

# Set in environment
API_KEY=<generated-key>
ADMIN_API_KEY=<generated-admin-key>
```

### 2. Database Security

- Use strong passwords
- Enable SSL/TLS for database connections
- Restrict network access to database
- Regular backups

### 3. Network Security

- Use HTTPS only in production
- Configure firewalls to restrict access
- Use private networks for inter-service communication
- Enable rate limiting (already configured)

### 4. Secrets Management

Use external secrets managers:

```bash
# AWS Secrets Manager
aws secretsmanager create-secret \
  --name threat-hunting/openai-key \
  --secret-string "sk-..."

# Kubernetes with External Secrets
kubectl apply -f external-secret.yaml
```

## Scaling

### Horizontal Scaling (Kubernetes)

Already configured with HPA (Horizontal Pod Autoscaler):

```bash
# Check HPA status
kubectl get hpa -n threat-hunting

# Scale manually
kubectl scale deployment analysis-engine --replicas=5 -n threat-hunting
```

### Vertical Scaling

Adjust resource limits in deployment:

```yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "4000m"
```

### Database Scaling

For high-volume scenarios:

1. **Use connection pooling** (already configured via SQLAlchemy)
2. **Read replicas** for read-heavy workloads
3. **Database sharding** for very large datasets

## Troubleshooting

### Common Issues

**1. API not starting:**

```bash
# Check logs
docker-compose logs analysis-engine

# Common issues:
# - Database connection failed: Check DB_CONNECTION_STRING
# - Port already in use: Change ANALYSIS_API_PORT
# - Missing dependencies: Rebuild image
```

**2. High memory usage:**

```bash
# Reduce concurrent analyses
MAX_CONCURRENT_ANALYSES=2

# Reduce streaming chunk size
STREAMING_CHUNK_SIZE=500
```

**3. Database connection errors:**

```bash
# Test database connectivity
psql -h localhost -U threat_hunter -d threat_hunting

# Check connection string format
DB_CONNECTION_STRING=postgresql://user:password@host:port/database
```

**4. LLM integration failing:**

```bash
# Check API key validity
export OPENAI_API_KEY=sk-...
python -c "import openai; print(openai.api_key)"

# Verify provider setting
LLM_PROVIDER=openai  # or anthropic
```

### Performance Tuning

**1. Analysis Engine:**

```bash
# Increase worker processes
API_WORKERS=4  # Match CPU cores

# Tune correlation window
CORRELATION_TIME_WINDOW_MINUTES=30  # Reduce for faster analysis
```

**2. Database:**

```bash
# Increase connection pool
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40

# Add database indexes (auto-created on startup)
```

**3. Streaming:**

For large telemetry files:

```bash
# Reduce memory footprint
STREAMING_CHUNK_SIZE=1000
```

## Health Checks

All services expose health endpoints:

```bash
# API health
curl http://localhost:8000/health

# Database health (via API)
curl http://localhost:8000/health | jq '.components.database'

# Full system health
curl http://localhost:8000/health | jq
```

## Backup & Recovery

### Database Backups

```bash
# Automated backups with Docker
docker exec postgres pg_dump -U threat_hunter threat_hunting > backup.sql

# Restore
docker exec -i postgres psql -U threat_hunter threat_hunting < backup.sql
```

### Generated Data

Backup output directories:

```bash
# Backup scenarios and analyses
tar -czf threat-hunting-backup-$(date +%Y%m%d).tar.gz ./output ./data
```

## Support

For issues and questions:

- GitHub Issues: https://github.com/yourusername/ai-threat-hunting-simulator/issues
- Documentation: https://github.com/yourusername/ai-threat-hunting-simulator/wiki
- Email: support@yourdomain.com
