# Python 3.12 slim image based on Debian Bookworm
FROM python:3.12-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py \
    WORKDIR=/opt/grepmarx

WORKDIR $WORKDIR

# Create a non-root user
RUN groupadd -r grepmarx && useradd -r -g grepmarx -d $WORKDIR grepmarx

# Install system dependencies, Node.js 20, and Dotnet 9.0 in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    wget \
    curl \
    ca-certificates \
    gnupg \
    openjdk-17-jdk \
    maven \
    gradle \
    golang \
    composer \
    git \
    && mkdir -p /var/log/supervisor /etc/supervisor/conf.d \
    # Install Node.js 20
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    # Install Dotnet Runtime 9.0
    && wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update && apt-get install -y --no-install-recommends dotnet-runtime-9.0 \
    # Cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install cdxgen as an npm global tool
RUN npm install -g @cyclonedx/cdxgen@12.1.4

# Install Python dependencies (Leverage Docker cache)
COPY requirements.txt requirements-pgsql.txt ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements-pgsql.txt

# Copy application source code and configurations
COPY entrypoint.sh run.py gunicorn-cfg.py supervisord-docker.conf ./
COPY .env-docker .env
COPY nginx nginx
COPY app app
COPY migrations migrations

# Uncomment and adjust to add custom certificates
#ADD ../certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
#RUN chmod 644 /etc/ssl/certs/ca-certificates.crt && update-ca-certificates

# Uncomment to add proxy configuration to maven settings
# RUN sed -i 's#</proxies>#<proxy>\n  <active>true</active>\n  <protocol>http</protocol>\n  <host>PROXY_IP</host>\n  <port>8080</port>\n</proxy>\n</proxies>#' /usr/share/maven/conf/settings.xml

# Set up directories and permissions
RUN mkdir -p data && \
    chmod +x entrypoint.sh && \
    mv supervisord-docker.conf /etc/supervisor/conf.d/supervisord.conf && \
    chown -R grepmarx:grepmarx $WORKDIR /var/log/supervisor /etc/supervisor/conf.d/

# Switch to the non-root user
USER grepmarx

EXPOSE 5005
#EXPOSE 443

ENTRYPOINT ["./entrypoint.sh"]
