FROM python:3.10.1

WORKDIR /opt/grepmarx

ENV FLASK_APP run.py

RUN apt-get update && apt-get install -y supervisor
RUN mkdir -p /var/log/supervisor
COPY supervisord-docker.conf /etc/supervisor/conf.d/supervisord.conf

COPY run.py celery_worker.py nginx gunicorn-cfg.py requirements.txt config.py .env ./
COPY grepmarx grepmarx
COPY third-party third-party

RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["/usr/bin/supervisord"]