FROM kalilinux/kali-rolling

# Update package list and install required tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    dirb \
    exploitdb \
    net-tools \
    iputils-ping \
    curl \
    wget \
    libcap2-bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash pentester && \
    usermod -aG sudo pentester

# Create virtual environment and install Python dependencies
RUN python3 -m venv /app/venv
COPY requirements.txt /app/requirements.txt
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Copy server files
COPY server.py /app/server.py
COPY entrypoint.sh /app/entrypoint.sh

# Set permissions
RUN chmod +x /app/entrypoint.sh && \
    chown -R pentester:pentester /app

# Set capabilities for network tools (allows non-root to use raw sockets)
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap

# Switch to non-root user
USER pentester

# Set working directory
WORKDIR /app

# Expose MCP port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MCP_SERVER_NAME="kali-pentest"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/venv/bin/python -c "import sys; sys.exit(0)" || exit 1

# Entry point
ENTRYPOINT ["/app/entrypoint.sh"]
