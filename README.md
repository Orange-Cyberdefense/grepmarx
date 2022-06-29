![Grepmarx](media/grepmarx-logo.png)

# Grepmarx - source code static analysis platform for security auditors

Grepmarx is a web application providing a single platform to quickly understand, analyze and identify vulnerabilities in possibly large and unknown code bases.

## Features

Code scanning capabilities
- Security code analysis (SAST - Static Analysis Security Testing)
- Multiple languages support: C/C++, C#, Go, HTML, Java, Kotlin, JavaScript, TypeScript, OCaml, PHP, Python, Ruby
- Multiple frameworks support: Spring, Django, Flask, jQuery, Express, Angular...

Analysis rules
- 1000+ existing analysis rules
- Easily extend analysis rules using Semgrep syntax: https://semgrep.dev/editor 
- Manage rules in rule packs to tailor code scanning

Extra
- Analysis workbench designed to efficiently browse scan results
- Scan code that doesn't compile
- Comprehensive LOC (Lines of Code) counter
- ... and a Dark Mode

## Screenshots

| Scan customization | Analysis workbench | Rule pack edition |
| ------ | ------ | ------ | 
| ![Scan customization](media/screen-1.png) | ![Analysis workbench](media/screen-2.png) | ![Rule pack edition](media/screen-3.png) |

## Requirements

| OS | CPU | Cores | RAM | Browser |
| ------ | ------ | ------ | ------ | ------ |
| GNU/Linux | 2.8Ghz | 4-6 | 12GB | IE9+, Edge (latest), Firefox (latest), Safari (latest), Chrome (latest), Opera (latest) |

## Build from sources

A Redis server is required to queue security scans. Install the `redis` package with your favorite distro package manager, then:
```bash
$ redis-server
```

```bash
$ # Get the code
$ git clone https://...grepmarx.git
$ cd grepmarx

$ # Virtualenv modules installation
$ virtualenv env
$ source env/bin/activate

$ # Install modules - SQLite Database
$ pip3 install -r requirements.txt
$ # OR with PostgreSQL connector
$ # pip install -r requirements-pgsql.txt

$ # Set the FLASK_APP environment variable
$ export FLASK_APP=run.py
$ # Set up the DEBUG environment
$ # export FLASK_ENV=development

$ # Start the celery worker process
$ celery -A app.celery_worker.celery worker --pool=solo --loglevel=info --detach

$ # Start the application (development mode)
$ # --host=0.0.0.0 - expose the app on all network interfaces (default 127.0.0.1)
$ # --port=5000    - specify the app port (default 5000)  
$ flask run --host=0.0.0.0 --port=5000

$ # Access grepmarx in browser: http://127.0.0.1:5000/
```

**Note: a default user account is created on first launch (user=admin / password=admin). Change the default password immediately.**

## Execution

Grepmarx is provided with a configuration to be executed in [Docker](https://www.docker.com/) and [Gunicorn](https://gunicorn.org/).

#### [Docker](https://www.docker.com/) execution
---

Make sure you have docker-composer installed on the system, and the docker daemon is running.
The application can then be easily executed in a docker container. The steps:

> Get the code

```bash
$ git clone https://...grepmarx.git
$ cd grepmarx
```

> Start the app in Docker

```bash
$ sudo docker-compose pull && sudo docker-compose build && sudo docker-compose up -d
```

Visit `http://localhost:5000` in your browser. The app should be up & running.


#### [Gunicorn](https://gunicorn.org/)
---

Gunicorn 'Green Unicorn' is a Python WSGI HTTP Server for UNIX. A supervisor configuration file is provided to start it along with the required Celery worker (used for security scans queuing).

> Install using pip

```bash
$ pip install gunicorn supervisor
```
> Start the app using gunicorn binary

```bash
$ supervisord -c supervisord.conf
```

Visit `http://localhost:8001` in your browser. The app should be up & running.

## Deployment

This quick guide assumes you want to deploy the application on an Ubuntu 20.04.2 LTS server, with gunicorn as the HTTP server, nginx as a reverse proxy and postgresql as the database server. Feel free to change any of that.

### Prepare the system

> Install required packages
```bash
$ sudo apt install python3-pip python3-venv postgresql redis-server nginx sudo python-tk python3-tk tk-dev libpq-dev
```

### Configure the database

> Create a dedicated postgresql user
```
$ sudo su postgres
$ createuser grepmarx
$ psql 
postgres=# ALTER USER grepmarx with encrypted password '<DB_PASSWORD>';
postgres=# exit
$ exit
```

> Edit the file `/etc/postgresql/12/main/pg_hba.conf` to use scram-sha-256 authentication
```
local   all         grepmarx                          scram-sha-256
```

> Restart PostgreSQL
```bash
$ sudo systemctl restart postgresql.service
```

### Prepare the application

> Create a dedicated system user
```bash
$ sudo useradd -m grepmarx
$ sudo passwd grepmarx
```


> Get the code, create a virtualenv and install the requirements
```bash
$ sudo su grepmarx
$ /bin/bash
$ cd
$ git clone https://.../grepmarx.git
$ sudo chown -R grepmarx:www-data grepmarx
$ cd grepmarx
$ python3 -m venv venv
$ source venv/bin/activate
$ (venv) $ pip install -r requirements-pgsql.txt
$ (venv) $ pip install -r requirements.txt
$ (venv) $ pip install -r requirements-mysql.txt
pip install flask_principal
$ (venv) $ deactivate
```

> Edit the `.env` file to activate production mode, define a secret key and set database configuration
```bash
$ cat .env 
DEBUG=False
SECRET_KEY=<APP_SECRET_KEY>
CELERY_BROKER_URL = redis://localhost:6379
RESULT_BACKEND = redis://localhost:6379
DB_ENGINE=postgresql
DB_NAME=grepmarx
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=grepmarx
DB_PASS=<DB_PASSWORD>
```

> Bind gunicorn to a system socket rather than a network port, by uncommenting the corresponding line in `supervisord.conf`
```
command=gunicorn -w 3 -t 300 --bind unix:grepmarx.sock run:app 
```

> Go back to your main user shell
```bash
$ exit
$ exit
```
> configure permission on grepmarx user 

```bash
$ sudo chmod -R u=rwX,g=rX,o=X /home/grepmarx/grepmarx
$ cd/home
$ sudo chmod u=X  grepmarx
``` 

### Configure systemd


> Create a service unit file for the application such as
```bash
$ cat /etc/systemd/system/grepmarx.service
[Unit]
Description=Grepmarx - supervisor launch gunicorn and celery worker
After=network.target

[Service]
User=grepmarx
Group=www-data
WorkingDirectory=/home/grepmarx/grepmarx
Environment="PATH=/home/grepmarx/grepmarx/venv/bin:/usr/bin"
ExecStart=/home/grepmarx/grepmarx/venv/bin/supervisord -n -c /home/grepmarx/grepmarx/supervisord.conf

[Install]
WantedBy=multi-user.target
```

> Start and enable the service

```bash
$ sudo systemctl enable grepmarx.service
$ sudo systemctl start grepmarx.service
```

### Configure nginx

> Create a nginx congiguration file for HTTP the application such as 
```bash
$ cat /etc/nginx/sites-available/grepmarx.conf
server {
    listen 80;
    server_name grepmarx-dev;
    client_max_body_size 0;

    location / {
        include proxy_params;
        proxy_pass http://unix:/home/grepmarx/grepmarx/grepmarx.sock;
    }
}
```

> Switch to https  by creatting a self-sign certificate and change nginx configuration

```bash
$ mkdir /etc/nginx/certificate
$ cd  /etc/nginx/certificate 
$ openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out cert.cert -keyout cert.key
```
 !! DONT COPY/PASTE !!

```bash
$ cat /etc/nginx/sites-available/grepmarx.conf

server {
    listen 80;
    return 301 https://172.18.19.50;
}

server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/certificate/cert.cert;
    ssl_certificate_key /etc/nginx/certificate/cert.key;
    server_name grepmarx_dev;

    location / {
        include proxy_params;
        proxy_pass http://unix:/home/grepmarx/grepmarx/grepmarx.sock;
    }

}

```

> Enable the configuration and restart nginx

```bash
$ sudo ln -s /etc/nginx/sites-available/grepmarx.conf /etc/nginx/sites-enabled
$ sudo rm /etc/nginx/sites-enabled/default
$ sudo systemctl restart nginx
```

Grepmarx is now be accessible through http://\<server\>. 

**Note: a default user account is created on first launch (user=admin / password=admin). Change the default password immediately.**

What you should do next:
- Get a certificate and activate TLS on nginx: http://nginx.org/en/docs/http/configuring_https_servers.html
- Harden nginx configuration: https://www.cisecurity.org/benchmark/nginx/
- Harden postgresql configuration: https://www.cisecurity.org/benchmark/postgresql/
- Harden system configuration: https://www.cisecurity.org/benchmark/ubuntu_linux/

## Credits & Links

- The web application dashboard is based on [AdminLTE Flask](https://github.com/app-generator/flask-dashboard-adminlte)
- Code scanning is powered by the [semgrep](https://semgrep.dev/) engine
- LOC counting is handled by [scc](https://github.com/boyter/scc)

<br />

---
Grepmarx - Provided by **[Orange Cyberdefense](https://orangecyberdefense.com)**.
