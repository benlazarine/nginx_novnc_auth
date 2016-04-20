from urlparse import urlparse, parse_qs

from flask import Flask, request
from itsdangerous import Signer, URLSafeTimedSerializer, BadSignature

app = Flask(__name__)
app.config.from_object('default_settings')
app.config.from_envvar('AUTH_SERVER_SETTINGS')


def _generate_test_signature(vm_ip, web_request):
    signer = Signer(app.config['SECRET_KEY'], app.config['SALT'])

    real_client_ip = web_request.environ.get('HTTP_X_REAL_IP', '')
    client_ip_signature = signer.get_signature(real_client_ip)

    user_agent = web_request.user_agent
    browser_fingerprint = str(user_agent)
    browser_fingerprint_signature = signer.get_signature(browser_fingerprint)

    usts = URLSafeTimedSerializer(app.config['SECRET_KEY'], app.config['SALT'])
    sig = usts.dumps([vm_ip, client_ip_signature, browser_fingerprint_signature])
    return sig


@app.route('/')
def auth():
    original_uri = request.environ.get('HTTP_X_ORIGINAL_URI', '')
    uri_parts = urlparse(original_uri)
    query_string = uri_parts.query
    query_vars = parse_qs(query_string)

    signature_list = query_vars.get('sig', '')
    if isinstance(signature_list, list):
        signature = signature_list[0]
    else:
        signature = signature_list

    try:
        ### TEST START
        # vm_ip = '128.196.64.214'
        # test_sig = _generate_test_signature(vm_ip, request)
        ### TEST END
        usts = URLSafeTimedSerializer(app.config['SECRET_KEY'], app.config['SALT'])
        sig_load_result = usts.loads(signature, max_age=app.config['MAX_AGE'])

        signer = Signer(app.config['SECRET_KEY'], app.config['SALT'])
        real_client_ip = request.environ.get('HTTP_X_REAL_IP', '')
        client_ip_signature = signer.get_signature(real_client_ip)
        assert client_ip_signature == sig_load_result[1]

        user_agent = request.user_agent
        browser_fingerprint = str(user_agent)
        browser_fingerprint_signature = signer.get_signature(browser_fingerprint)
        assert browser_fingerprint_signature == sig_load_result[2]

        auth_result_code = 200
    except BadSignature as e:
        auth_result_code = 401

    return 'Auth result', int(auth_result_code)


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8888)
