# Nginx NoNVC Auth

Provides a subrequest server for verifying the authenticity of transparent proxy requests

# Dependencies & Setup

- nginx
- uwsgi
- python-uwsgi-plugin
- _python packages in requirements.txt_


# Configuration

The following variables will need to be defined:

```
WEB_DESKTOP_SIGNING_SECRET_KEY = '<signing-secret-key-value>'
WEB_DESKTOP_SIGNING_SALT = '<signing-salt-secret-value>'
WEB_DESKTOP_FP_SECRET_KEY = '<fingerprint-secret-key-value>'
WEB_DESKTOP_FP_SALT = '<fingerprint-salt-secret-value>'
MAX_AGE = # (int) max age for a timed signature to be considered valid
```

# Authors
- Julian Pistorius
- Andrew Lenards
- Steve Gregory
