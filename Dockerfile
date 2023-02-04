FROM python:3.11.1

WORKDIR /opt/grepmarx

ENV FLASK_APP run.py

RUN apt-get update

# Supervisord install & configuration
RUN apt-get install -y supervisor
RUN mkdir -p /var/log/supervisor
COPY supervisord-docker.conf /etc/supervisor/conf.d/supervisord.conf

# Copy required files into the container
COPY entrypoint.sh run.py gunicorn-cfg.py requirements.txt requirements-pgsql.txt ./
COPY .env-docker .env
COPY nginx nginx
COPY app app
COPY migrations migrations
RUN mkdir data

# Install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements-pgsql.txt

# Dependency scan (cdxgen / depscan) requirements
RUN apt-get install -y npm openjdk-17-jdk maven gradle golang
RUN npm install -g @appthreat/cdxgen

# Downloaded packages cleaning
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 5000
#EXPOSE 443

RUN chmod u+x ./entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]