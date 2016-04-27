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

## Nginx

We use a `/etc/nginx/locations` directory to specific the locations for a site. Any conf(s) defined within `<base-repo>/nginx/locations` should be symlinked into `/etc/nginx/locations`.

We include this path within the symlinked `/etc/nginx/sites-enabled/site.conf`:

```
server {
    listen  443;
    # ...
    # ...
    # at the bottom
    include locations/*.conf;
}
```

# Authors
- Julian Pistorius
- Andrew Lenards
- Steve Gregory
