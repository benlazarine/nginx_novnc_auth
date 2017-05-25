import logging
import sys

from logging.handlers import RotatingFileHandler
from urlparse import urlparse, parse_qs

from flask import Flask, request, render_template
from itsdangerous import BadSignature

import default_settings

from signatures import decode_signature, generate_signature


app = Flask(__name__)
app.config.from_object(default_settings)
app.config.from_envvar('AUTH_SERVER_SETTINGS', silent=False)
app.config['PROPAGATE_EXCEPTIONS'] = True

@app.route('/error/')
@app.route('/error/<error_code>')
def error_handler():
    app.logger.debug('NEW ERROR REQUEST')
    app.logger.debug("error code = %s" % error_code)
    return render_template('error_page.html', error_code=error_code)
    

@app.route('/auth/')
def auth():
    app.logger.debug('NEW AUTH REQUEST')

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
        vm_ip = signature_values[0]
        auth_result_code = 200
    except BadSignature as e:
        vm_ip = ''
        auth_result_code = 401

    if auth_result_code != 200:
        return render_template('error_page.html', error_code=auth_result_code)

    headers = {}
    if vm_ip and fingerprint_is_valid:
        headers['X-Target-VM-IP'] = vm_ip
    if signature and fingerprint_is_valid:
        headers['X-Set-Sig-Cookie'] = 'token=%s' % signature
        headers['X-Set-Display-Cookie'] = 'password=display'

    app.logger.debug('Sending back headers: %s', headers)
    app.logger.debug('auth_request result code: %s', auth_result_code)

    return (vm_ip, int(auth_result_code), headers)

