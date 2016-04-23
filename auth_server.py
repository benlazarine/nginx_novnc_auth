import logging
from urlparse import urlparse, parse_qs

from flask import Flask, request
from itsdangerous import BadSignature

from signatures import decode_signature, validate_fingerprints, generate_signature

app = Flask(__name__)
app.config.from_object('default_settings')
app.config.from_envvar('AUTH_SERVER_SETTINGS')


@app.route('/')
def auth():
    # Get all our prerequisites ready.
    original_uri = request.environ.get('HTTP_X_ORIGINAL_URI', '')
    user_agent = str(request.user_agent)
    client_ip = request.environ.get('HTTP_X_REAL_IP', '')
    accept = request.environ.get('HTTP_ACCEPT', '')
    accept_encoding = request.environ.get('HTTP_ACCEPT_ENCODING', '')
    accept_language = request.environ.get('HTTP_ACCEPT_LANGUAGE', '')
    uri_parts = urlparse(original_uri)
    query_string = uri_parts.query
    query_vars = parse_qs(query_string)
    signature_list = query_vars.get('sig', '')
    if isinstance(signature_list, list):
        signature = signature_list[0]
    else:
        signature = signature_list

    # Check signatures
    try:
        sig_load_result = decode_signature(app.config['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                                           app.config['WEB_DESKTOP_SIGNING_SALT'],
                                           app.config['MAX_AGE'],
                                           signature)

        (signature_values, timestamp) = sig_load_result
        (vm_ip, client_ip_fingerprint, browser_fingerprint) = signature_values

        if app.debug:
            # Generate a signature with the expected values, for testing.
            test_signature = generate_signature(app.config['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                                                app.config['WEB_DESKTOP_SIGNING_SALT'],
                                                app.config['WEB_DESKTOP_FP_SECRET_KEY'],
                                                app.config['WEB_DESKTOP_FP_SALT'],
                                                client_ip,
                                                vm_ip,
                                                user_agent,
                                                accept,
                                                accept_encoding,
                                                accept_language)
            logging.debug('test_signature: %s', test_signature)

        is_valid = validate_fingerprints(app.config['WEB_DESKTOP_FP_SECRET_KEY'],
                                         app.config['WEB_DESKTOP_FP_SALT'],
                                         client_ip_fingerprint,
                                         browser_fingerprint,
                                         client_ip,
                                         user_agent,
                                         accept,
                                         accept_encoding,
                                         accept_language)

        if not is_valid:
            auth_result_code = 401
        else:
            auth_result_code = 200
    except BadSignature as e:
        vm_ip = None
        auth_result_code = 401

    headers = {'X-Target-VM-IP': vm_ip}

    return (vm_ip, int(auth_result_code), headers)


if __name__ == '__main__':
    if app.debug:
        logging.root.setLevel(logging.DEBUG)
    app.run(debug=app.debug, host='127.0.0.1', port=8888)
