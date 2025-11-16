FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY generator/ ./generator/
COPY analysis_engine/ ./analysis_engine/

# Expose API port
EXPOSE 8000

# Run API server
CMD ["python", "-m", "uvicorn", "analysis_engine.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
