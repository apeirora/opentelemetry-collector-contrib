# OpenTelemetry Collector with AuditLog Receiver

This project provides a Dockerized OpenTelemetry Collector with an auditlog receiver, debug exporter, and file storage extension.

## Features

- **AuditLog Receiver**: HTTP endpoint for receiving audit logs
- **Debug Exporter**: Console output for debugging
- **File Storage**: Persistent storage for audit logs
- **Circuit Breaker**: Protection against failures
- **Docker Support**: Easy deployment with Docker

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Build and run
docker-compose up --build

# Run in background
docker-compose up -d --build
```

### Using Docker directly

```bash
# 1. Build the Linux binary
GOOS=linux GOARCH=amd64 make otelcontribcol

# 2. Build Docker image
docker build -t otelcontribcol-auditlog .

# 3. Run container
docker run -d \
  --name otel-collector-auditlog \
  -p 8080:8080 \
  -v $(pwd)/storage:/var/lib/otelcol/storage \
  otelcontribcol-auditlog
```

## Configuration

The collector is configured via `auditlog-config.yaml`:

- **Receiver**: `auditlogreceiver` on port 8080
- **Storage**: File storage in `/var/lib/otelcol/storage`
- **Exporter**: Debug exporter with detailed output
- **No processors** (direct pipeline)

## Testing

Send audit logs to the collector:

```bash
curl -X POST http://localhost:8080/v1/logs \
  -H "Content-Type: application/json" \
  -d '{"message": "Test audit log", "timestamp": "2024-01-01T00:00:00Z"}'
```

## Endpoints

- **AuditLog Receiver**: `http://localhost:8080/v1/logs`
- **OTLP gRPC**: `localhost:4317` (optional)
- **OTLP HTTP**: `localhost:4318` (optional)

## GitHub Actions

The project includes a GitHub Action that automatically builds and pushes Docker images to GitHub Container Registry on:

- Push to `main` or `AuditLogReceiver` branches
- Pull requests
- Git tags (semantic versioning)

## File Structure

```
├── Dockerfile                 # Main Dockerfile
├── docker-compose.yml        # Docker Compose configuration
├── auditlog-config.yaml      # Collector configuration
├── .github/workflows/        # GitHub Actions
└── storage/                  # Persistent storage directory
```

## Development

### Local Development

```bash
# Build locally
make otelcontribcol

# Run with local config
./bin/otelcontribcol_windows_amd64.exe --config=auditlog-config.yaml
```

### Docker Development

```bash
# Build and run
docker-compose up --build

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Troubleshooting

### Permission Issues

If you encounter permission issues with storage:

```bash
# Create storage directory with proper permissions
mkdir -p storage
chmod 755 storage
```

### Container Not Starting

Check container logs:

```bash
docker logs otel-collector-auditlog
```

### Port Already in Use

Change the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "8081:8080"  # Use port 8081 instead
```
