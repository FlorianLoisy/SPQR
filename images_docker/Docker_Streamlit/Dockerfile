FROM python:3.9-slim

# Install system dependencies and Docker CLI
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python requirements
COPY scripts/spqr_app/requirements.txt .
RUN pip install -r requirements.txt

# Set environment variables
ENV PYTHONPATH=/app
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Command to run Streamlit
CMD ["streamlit", "run", "/app/scripts/spqr_app/app.py"]
