# Base Image — Bookworm has OpenSSL 3.x (needed by bleeding-jumbo john binary)
FROM python:3.11-slim-bookworm

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies + system john (guaranteed to work on Render)
RUN apt-get update && apt-get install -y \
    perl \
    libssl3 \
    john \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Install Python requirements
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Copy John the Ripper bleeding-jumbo (local compiled version - faster)
# If this binary works on Render's Linux, it will be preferred by crack_worker.py
COPY john-bleeding-jumbo/ ./john-bleeding-jumbo/

# Make local JTR binary executable (system john is already in PATH)
RUN chmod +x /app/john-bleeding-jumbo/run/john \
    && chmod +x /app/john-bleeding-jumbo/run/pdf2john.pl \
    && mkdir -p /app/app/uploads

# Port
EXPOSE 8000

# Command to run
WORKDIR /app/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
