from flask import Config

from signatures import generate_signature, decode_signature, validate_fingerprints


def generate_signature_01(conf, request_data):
    client_ip = request_data['client_ip']
    vm_ip = request_data['vm_ip']
    user_agent = request_data['user_agent']
    accept = request_data['accept']
    accept_encoding = request_data['accept_encoding']
    accept_language = request_data['accept_language']

    sig = generate_signature(conf['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                             conf['WEB_DESKTOP_SIGNING_SALT'],
                             conf['WEB_DESKTOP_FP_SECRET_KEY'],
                             conf['WEB_DESKTOP_FP_SALT'],
                             client_ip,
                             vm_ip,
                             user_agent,
                             accept,
                             accept_encoding,
                             accept_language)
    return sig


def decode_signature_02(conf, signature):
    values = decode_signature(conf['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                              conf['WEB_DESKTOP_SIGNING_SALT'],
                              conf['MAX_AGE'],
                              signature)

    return values


def validate_fingerprints_03(conf, values, request_data):
    client_ip = request_data['client_ip']
    user_agent = request_data['user_agent']
    accept = request_data['accept']
    accept_encoding = request_data['accept_encoding']
    accept_language = request_data['accept_language']

    (vm_ip, client_ip_fingerprint, browser_fingerprint) = values

    is_valid = validate_fingerprints(conf['WEB_DESKTOP_FP_SECRET_KEY'],
                                     conf['WEB_DESKTOP_FP_SALT'],
                                     client_ip_fingerprint,
                                     browser_fingerprint,
                                     client_ip,
                                     user_agent,
                                     accept,
                                     accept_encoding,
                                     accept_language)
    return is_valid


if __name__ == '__main__':
    conf = Config('..')
    test_request_data = dict(
        accept_encoding='Accept-Encoding: gzip, deflate, sdch',
        accept_language='Accept-Language: en-US,en;q=0.8',
        accept='Accept: application/json, text/javascript, */*; q=0.01',
        user_agent='User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36',
        vm_ip='128.196.64.214',
        client_ip='127.0.0.1'
    )

    conf.from_pyfile('default_settings.py')
    # conf.from_pyfile('local_settings.py')

    signature = generate_signature_01(conf, test_request_data)
    print signature
    values, timestamp = decode_signature_02(conf, signature)
    print values
    is_valid = validate_fingerprints_03(conf, values, test_request_data)
    print is_valid
