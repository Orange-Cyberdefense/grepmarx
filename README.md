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

### How to use it

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
$ celery -A celery_worker.celery worker --pool=solo --loglevel=info --detach

$ # Start the application (development mode)
$ # --host=0.0.0.0 - expose the app on all network interfaces (default 127.0.0.1)
$ # --port=5000    - specify the app port (default 5000)  
$ flask run --host=0.0.0.0 --port=5000

$ # Access grepmarx in browser: http://127.0.0.1:5000/
```

**Note: On first launch, call `/init` to initialize the database and create a default user account (user=admin / password=admin). Change the default password immediately.**

### Deployment

Grepmarx is provided with a configuration to be executed in [Docker](https://www.docker.com/) and [Gunicorn](https://gunicorn.org/).

#### [Docker](https://www.docker.com/) execution
---

Make sure you have docker-composed installed on the system, and the docker daemon is running.
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

Visit `http://localhost:5005` in your browser. The app should be up & running.


#### [Gunicorn](https://gunicorn.org/)
---

Gunicorn 'Green Unicorn' is a Python WSGI HTTP Server for UNIX.

> Install using pip

```bash
$ pip install gunicorn
```
> Start the app using gunicorn binary

```bash
$ gunicorn --bind 0.0.0.0:8001 run:app
Serving on http://localhost:8001
```

Visit `http://localhost:8001` in your browser. The app should be up & running.


### Credits & Links

- The web application dashboard is based on [AdminLTE Flask](https://github.com/app-generator/flask-dashboard-adminlte)
- Code scanning is performed through the [libsast](https://github.com/ajinabraham/libsast) library, which is powered by the [semgrep](https://semgrep.dev/) engine
- LOC counting is handled by [pygount](https://github.com/roskakori/pygount)

<br />

## TODO
- Dashboard
- Display handling of WTForms errors
- Code dependency checking
- Application inspection features

---
Grepmarx - Provided by **[Orange Cyberdefense](https://orangecyebrdefense.com)**.
