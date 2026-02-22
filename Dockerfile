# Ubuntu 24.04 has GLIBC 2.39
FROM ubuntu:24.04

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies + build tools for John
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    perl \
    libssl-dev \
    libgomp1 \
    zlib1g-dev \
    build-essential \
    yasm \
    pkg-config \
    libgmp-dev \
    libbz2-dev \
    git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Workdir
WORKDIR /app

# Install Python requirements
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Copy John the Ripper bleeding-jumbo source
COPY john-bleeding-jumbo/ ./john-bleeding-jumbo/

# Build John from source to ensure compatibility with Render's hardware
WORKDIR /app/john-bleeding-jumbo/src
RUN ./configure --disable-native-tests && \
    make -s clean && \
    make -sj$(nproc)

# Move back to /app
WORKDIR /app

# Make artifacts executable + create uploads dir
RUN chmod +x /app/john-bleeding-jumbo/run/john \
    && chmod +x /app/john-bleeding-jumbo/run/pdf2john.pl \
    && mkdir -p /app/app/uploads

# Port
EXPOSE 8000

# Command to run
WORKDIR /app/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
