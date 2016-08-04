import logging
import sys
from logging.handlers import RotatingFileHandler

from urlparse import urlparse, parse_qs

from flask import Flask, request
from itsdangerous import BadSignature

import default_settings
from signatures import decode_signature, validate_fingerprints, generate_signature

app = Flask(__name__)
app.config.from_object(default_settings)
app.config.from_envvar('AUTH_SERVER_SETTINGS', silent=False)
app.config['PROPAGATE_EXCEPTIONS'] = True

@app.route('/auth/')
def auth():
    # TODO:
    # - For websockets check that the 'Origin' header is set to http(s)://kurtz.iplantcollaborative.org or whatever.
    app.logger.debug('NEW AUTH REQUEST')


    from pprint import pprint
    app.logger.info("Flask configuration:\n %s \n\n" % app.config)
    logging.warn(pprint(request.environ))
    logging.warn(app.logger)
    logging.warn("--------------------------------")
    logging.warn(request.cookies)

    # Get all our prerequisites ready.
    original_uri = request.environ.get('ORIGINAL_URI', '')
    user_agent = str(request.user_agent)
    client_ip = request.environ.get('REMOTE_ADDR', '')
    accept_language = request.environ.get('HTTP_ACCEPT_LANGUAGE', '')

    uri_parts = urlparse(original_uri)
    query_string = uri_parts.query
    query_vars = parse_qs(query_string)
    signature_list = query_vars.get('token', '')

    app.logger.debug('original_uri: %s', original_uri)
    app.logger.debug('user_agent: %s', user_agent)
    app.logger.debug('client_ip: %s', client_ip)
    app.logger.debug('accept_language: %s', accept_language)
    app.logger.debug('query_string: %s', query_string)

    if not signature_list:
        # might need to move this to request.environ.get('HTTP_COOKIE')
        app.logger.debug('No signature in the query string, trying cookies.')
        signature_list = request.cookies.get('token', '')
    if isinstance(signature_list, list):
        signature = signature_list[0]
    else:
        signature = signature_list
    if not signature:
        app.logger.warn('No signature found in either query string or cookies.')
    else:
        app.logger.debug('Signature found: %s', signature_list)

    fingerprint_is_valid = False
    # Check signatures
    try:
        sig_load_result = decode_signature(app.config['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                                           app.config['WEB_DESKTOP_SIGNING_SALT'],
                                           app.config['MAX_AGE'],
                                           signature)

        (signature_values, timestamp) = sig_load_result
        (vm_ip, client_ip_fingerprint, browser_fingerprint) = signature_values

        fingerprint_is_valid = validate_fingerprints(app.config['WEB_DESKTOP_FP_SECRET_KEY'],
                                                     app.config['WEB_DESKTOP_FP_SALT'],
                                                     client_ip_fingerprint,
                                                     browser_fingerprint,
                                                     client_ip,
                                                     user_agent,
                                                     accept_language)

        if not fingerprint_is_valid:
            auth_result_code = 401
        else:
            auth_result_code = 200
    except BadSignature as e:
        vm_ip = ''
        auth_result_code = 401

    headers = {}
    if vm_ip and fingerprint_is_valid:
        headers['X-Target-VM-IP'] = vm_ip
    if signature and fingerprint_is_valid:
        headers['X-Set-Sig-Cookie'] = 'token=%s' % signature
        headers['X-Set-Display-Cookie'] = 'password=display'

    app.logger.debug('Sending back headers: %s', headers)
    app.logger.debug('auth_request result code: %s', auth_result_code)

    return (vm_ip, int(auth_result_code), headers)


if __name__ == '__main__':
    handler = RotatingFileHandler('/opt/nginx_novnc_auth/logs/novnc_auth.log',
                                  maxBytes=10485760, backupCount=2)
    print "App Path: %s" % sys.path
    if app.debug:
        logging.root.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.ERROR)

    app.logger.addHandler(handler)
    ssl_crt = "/etc/letsencrypt/live/kurtz.cyverse.org/cert.pem"
    ssl_key = "/etc/letsencrypt/live/kurtz.cyverse.org/privkey.pem"
    #context = ('/etc/ssl/certs/iplantc.org.crt', '/etc/ssl/private/iplantc.key')
    context = (ssl_crt, ssl_key)
    #app.run(debug=app.debug, host='127.0.0.1', port=5000)
    # We will try this first, otherwise back to top?
    app.logger.debug('Before app run call ...')
    # THIS WORKS!
    # app.run(debug=app.debug, host='kurtz.iplantc.org', ssl_context=context, threaded=True, port=5000)  # I made some changes.. Note: ssl_context, and host changed
    app.run(debug=app.debug, host='kurtz.cyverse.org', ssl_context=context, threaded=True, port=5000)  # I made some changes.. Note: ssl_context, and host changed
