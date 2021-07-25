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

$ # Start the application (development mode)
$ # --host=0.0.0.0 - expose the app on all network interfaces (default 127.0.0.1)
$ # --port=5000    - specify the app port (default 5000)  
$ flask run --host=0.0.0.0 --port=5000

$ # Access grepmarx in browser: http://127.0.0.1:5000/
```

**Note: On first launch, call `/init` to initialize the database and create a default user account (user=admin / password=admin). Change the default password immediately.**

### Deployment

Grepmarx is provided with a basic configuration to be executed in [Docker](https://www.docker.com/), [Heroku](https://www.heroku.com/), and [Gunicorn](https://gunicorn.org/).

#### [Docker](https://www.docker.com/) execution
---

The application can be easily executed in a docker container. The steps:

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


#### [Heroku](https://www.heroku.com/)
---

Steps to deploy on **Heroku**

- [Create a FREE account](https://signup.heroku.com/) on Heroku platform
- [Install the Heroku CLI](https://devcenter.heroku.com/articles/getting-started-with-python#set-up) for GNU/Linux
- Open a terminal window and authenticate via `heroku login` command
- Clone the sources and push the project for LIVE deployment

```bash
$ # Clone the source code:
$ git clone https://...grepmarx.git
$ cd grepmarx

$ # Check Heroku CLI is installed
$ heroku -v
heroku/7.25.0 win32-x64 node-v12.13.0 # <-- All good

$ # Check Heroku CLI is installed
$ heroku login
$ # this command will open a browser window - click the login button (in browser)

$ # Create the Heroku project
$ heroku create

$ # Trigger the LIVE deploy
$ git push heroku master

$ # Open the LIVE app in browser
$ heroku open
```

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
- Rule repository management
- Display handling of WTForms errors
- Database is locked during a scan / rule refresh
- Line counting optimization
- Dashboard
- Scan and rule refresh in background
- Code dependency checking
- Application inspection features

---
Grepmarx - Provided by **[Orange Cyberdefense](https://orangecyebrdefense.com)**.
