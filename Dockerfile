# Dockerfile for BharatOSINT MVP
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies and spaCy model
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm

# Copy application files
COPY backend/ ./backend/
COPY static/ ./static/
COPY data/ ./data/
COPY evaluation/ ./evaluation/
COPY README.md .

# Seed initial database if not present
RUN python -m backend.ingest

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
