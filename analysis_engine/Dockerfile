FROM python:3.11-slim

WORKDIR /app

# python-magic (upload MIME checks) needs the libmagic shared library
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY config.py ./
COPY generator/ ./generator/
COPY analysis_engine/ ./analysis_engine/
COPY detection_rules/ ./detection_rules/

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Run API server
CMD ["python", "-m", "uvicorn", "analysis_engine.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
