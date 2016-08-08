"""
WSGI entry point for nginx_novnc_auth transparent proxy

This module contains the Flask app exposes as a WSGI callable.
It has been convention to refer to this _callable_ as  `application`
but could be configured to another name (e.g. `app`) using the
`callable` attribute in the [uwsgi] section of the ini file:

See novnc_auth.uwsgi.ini within this repository.
"""

import os
import sys
import logging


root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))

if os.environ.has_key("VIRTUAL_ENV_PATH"):
  virtual_env_path = os.environ["VIRTUAL_ENV_PATH"]
else:
  virtual_env_path = "/opt/env/nginx_novnc_auth/lib/python2.7/site-packages"

sys.path.insert(0, virtual_env_path)
sys.path.insert(1, root_dir)

os.environ["AUTH_SERVER_SETTINGS"] = os.path.join(root_dir, "local_settings.py")


# Ensure the settings are set prior to `import` of Flask app
from auth_server import app

from logging.handlers import RotatingFileHandler
from logging import Formatter

log_file = os.path.join(root_dir, 'logs/novnc_auth.log')

handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=2)
fmt = Formatter(
        "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
handler.setFormatter(fmt)

if 'DEBUG' in app.config:
    app.debug = app.config['DEBUG']

if app.debug:
    handler.setLevel(logging.DEBUG)
else:
    handler.setLevel(logging.ERROR)

app.logger.addHandler(handler)

app.logger.debug('Starting ...%s ' % log_file)

application = app

