FROM python:3.11-slim

WORKDIR /app

# Install minimal dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV FLASK_APP=pentestlab_api.py
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["python", "pentestlab_api.py"]
# Use official Python runtime as base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements_pro.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements_pro.txt

# Copy application code
COPY vulnshop_pro.py .
COPY Dashboard_Interactive.html .
COPY vulnerabilities_db.json .

# Create logs directory
RUN mkdir -p logs

# Set environment variables
ENV FLASK_APP=vulnshop_pro.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Expose port
EXPOSE 5000

# Run with Gunicorn
CMD ["gunicorn", \
     "--worker-class", "sync", \
     "--workers", "4", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "vulnshop_pro:app"]
