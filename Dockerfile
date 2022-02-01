FROM python:3.10.1

WORKDIR /opt/grepmarx

ENV FLASK_APP run.py

RUN apt-get update && apt-get install -y supervisor && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/log/supervisor
COPY supervisord-docker.conf /etc/supervisor/conf.d/supervisord.conf

COPY run.py gunicorn-cfg.py requirements.txt .env ./
COPY nginx nginx
COPY app app

RUN rm -fr app/db.sqlite3 # just in case

# install python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000
CMD /usr/bin/supervisord