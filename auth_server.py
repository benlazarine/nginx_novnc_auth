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


@app.route('/auth/')
def auth():
    # TODO:
    # - For websockets check that the 'Origin' header is set to http(s)://kurtz.iplantcollaborative.org or whatever.
    app.logger.debug('NEW AUTH REQUEST')
    # Get all our prerequisites ready.
    original_uri = request.environ.get('HTTP_X_ORIGINAL_URI', '')
    app.logger.debug('original_uri: %s', original_uri)
    user_agent = str(request.user_agent)
    app.logger.debug('user_agent: %s', user_agent)
    client_ip = request.environ.get('HTTP_X_REAL_IP', '')
    app.logger.debug('client_ip: %s', client_ip)
    accept_language = request.environ.get('HTTP_ACCEPT_LANGUAGE', '')
    app.logger.debug('accept_language: %s', accept_language)
    uri_parts = urlparse(original_uri)
    query_string = uri_parts.query
    app.logger.debug('query_string: %s', query_string)
    query_vars = parse_qs(query_string)
    signature_list = query_vars.get('token', '')
    if not signature_list:
        app.logger.debug('No signature in the query string, trying cookies.')
        signature_list = request.cookies.get('token', '')
    if isinstance(signature_list, list):
        signature = signature_list[0]
    else:
        signature = signature_list
    if not signature:
        logging.warn('No signature found in either query string or cookies.')
    else:
        app.logger.debug('Signature found: %s', signature_list)

    fingerprint_is_valid = False
    # Check signatures
    try:
        if app.debug:
            # Generate a signature with the expected values, for testing.
            # We dn't have the vm_ip yet, so hard-code it. That way we can
            # pre-generate a signature which should work.
            manual_vm_ip = '128.196.65.182'
            manual_signature = generate_signature(app.config['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                                                  app.config['WEB_DESKTOP_SIGNING_SALT'],
                                                  app.config['WEB_DESKTOP_FP_SECRET_KEY'],
                                                  app.config['WEB_DESKTOP_FP_SALT'],
                                                  client_ip,
                                                  manual_vm_ip,
                                                  user_agent,
                                                  accept_language)
            app.logger.debug('manual_signature: %s', manual_signature)

        sig_load_result = decode_signature(app.config['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                                           app.config['WEB_DESKTOP_SIGNING_SALT'],
                                           app.config['MAX_AGE'],
                                           signature)

        (signature_values, timestamp) = sig_load_result
        (vm_ip, client_ip_fingerprint, browser_fingerprint) = signature_values

        if app.debug:
            # Generate a signature with the expected values, for testing.
            expected_signature = generate_signature(app.config['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                                                    app.config['WEB_DESKTOP_SIGNING_SALT'],
                                                    app.config['WEB_DESKTOP_FP_SECRET_KEY'],
                                                    app.config['WEB_DESKTOP_FP_SALT'],
                                                    client_ip,
                                                    vm_ip,
                                                    user_agent,
                                                    accept_language)
            app.logger.debug('expected_signature: %s', expected_signature)

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
    app.logger.debug('Sending back headers: %s', headers)
    return (vm_ip, int(auth_result_code), headers)


if __name__ == '__main__':
    if app.debug:
        logging.root.setLevel(logging.DEBUG)
    app.run(debug=app.debug, host='127.0.0.1', port=5000)
