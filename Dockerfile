# Base Image
FROM python:3.11-slim-bullseye

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
# Default JTR path for Docker
ENV JOHN_RUN_DIR=/app/john-bleeding-jumbo/run

# Install system dependencies
RUN apt-get update && apt-get install -y \
    perl \
    libssl1.1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Install Python requirements
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and JTR folder
COPY app/ ./app/
COPY john-bleeding-jumbo/ ./john-bleeding-jumbo/

# Ensure JTR is executable
RUN chmod +x /app/john-bleeding-jumbo/run/john \
    && chmod +x /app/john-bleeding-jumbo/run/pdf2john.pl \
    && mkdir -p /app/app/uploads

# Port
EXPOSE 8000

# Command to run (moving into 'app' folder context if needed)
WORKDIR /app/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
