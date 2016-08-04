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

log_file = os.path.join(root_dir, 'logs/novnc_auth.log')

handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=2)
fmt = logging.Formatter(FORMAT,datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(fmt)

app.debug = False

if app.debug:
    logging.root.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
else:
    handler.setLevel(logging.ERROR)

app.logger.addHandler(handler)

app.logger.debug('Starting ...%s '% log_file)
app.logger.debug(app.__dict__)

application = app

