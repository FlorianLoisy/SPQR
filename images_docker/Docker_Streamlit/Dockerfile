FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    python3-dev \
    gcc \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    xdg-utils \
    lsb-release && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create necessary directories
RUN mkdir -p /data/output/pcap

# Copy configuration files
COPY .streamlit /app/.streamlit
COPY config /app/config
COPY requirements.txt .
COPY setup.py /app/
RUN pip install -e /app/
RUN pip install -r requirements.txt
RUN pip install scapy>=2.5.0

# Set environment variables
ENV PYTHONPATH=/app
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV PCAP_OUTPUT_DIR=/data/output/pcap

# Set permissions
RUN chmod -R 777 /data/output/pcap

# Command to run Streamlit
CMD ["streamlit", "run", "/app/scripts/spqr_app/app.py"]
