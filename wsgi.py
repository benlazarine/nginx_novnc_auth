import os
import sys
import logging
from logging.handlers import RotatingFileHandler

from auth_server import app

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if os.environ.has_key("VIRTUAL_ENV_PATH"):
  virtual_env_path = os.environ["VIRTUAL_ENV_PATH"]
else:
  virtual_env_path = "/opt/env/nginx_novnc_auth/lib/python2.7/site-packages"

sys.path.insert(0, virtual_env_path)
sys.path.insert(1, root_dir)

def run_main():
    log_file = os.path.join(root_dir, 'nginx_novnc_auth/logs/novnc_auth.log')
    handler = RotatingFileHandler(
        log_file,
        maxBytes=10485760, backupCount=2)

    app.debug = False
    if app.debug:
        logging.root.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.ERROR)
    app.logger.addHandler(handler)

    app.logger.debug('Starting ...%s '% log_file)
    app.logger.debug(app.__dict__)

    context = ('/etc/ssl/certs/iplantc.org.crt', '/etc/ssl/private/iplantc.key')
    #app.run(debug=app.debug, port=5000)
    app.run(debug=app.debug, host='kurtz.iplantc.org', ssl_context=context, threaded=True, port=5000, use_reloader=False)


if __name__ == "__main__":
    run_main()
#NOTE: __name__ == 'nginx_novnc_auth.wsgi' when executed by service
# if 'wsgi' in __name__:
#     run_main()

