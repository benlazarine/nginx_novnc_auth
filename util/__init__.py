from flask import Config
from itsdangerous import Signer, URLSafeTimedSerializer


def generate_test_signature(signing_secret_key, signing_salt, fp_secret_key, fp_salt, client_ip, vm_ip, user_agent,
                            accept, accept_encoding, accept_language):
    """ Generate test signatures.

    Notes from @lenards:

    1. Creating the signed value:
    SIGNED_SERIALIZER = URLSafeTimedSerializer(
        settings.WEB_DESKTOP['signing']['SECRET_KEY'],
        salt=settings.WEB_DESKTOP['signing']['SALT'])

    SIGNER = Signer(
        settings.WEB_DESKTOP['fingerprint']['SECRET_KEY'],
        salt=settings.WEB_DESKTOP['fingerprint']['SALT'])

    client_ip = '127.0.0.1'
    client_ip_fingerprint = SIGNER.get_signature(client_ip)
    browser_fingerprint = SIGNER.get_signature(''.join([
        request.META['HTTP_USER_AGENT'],
        request.META['HTTP_ACCEPT'],
        request.META['HTTP_ACCEPT_ENCODING'],
        request.META['HTTP_ACCEPT_LANGUAGE']]))

    sig = SIGNED_SERIALIZER.dumps([ip_address,
        client_ip_fingerprint,
        browser_fingerprint])


    2. Test curl request:
    curl 'https://api.atmo.dev/api/v1/maintenance' -H 'Origin: https://ui.atmo.dev' -H 'Accept-Encoding: gzip, deflate, sdch' -H 'Accept-Language: en-US,en;q=0.8' -H 'Authorization: Token fe5ce63617af95898fa6973774c64f81' -H 'Content-Type: application/json' -H 'Accept: application/json, text/javascript, */*; q=0.01' -H 'Referer: https://ui.atmo.dev/application/projects/3277/instances/25286' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36' -H 'Connection: keep-alive' --compressed --insecure

    3. Should generate a redirect like:
    https://kurtz.iplantcollaborative.org/?sig=WyIxMjguMTk2LjY0LjIxNCIsIll2OUtONXhZTGcxYzdzU2tYQ0trb2x6RnBRayIsIlZkS28yemhidVJpQ3Z6WDZmTnNJRUVWdWcydyJd.CfsDWA.1tUUGb1772CZPn5IlttHM82qiuA

    4. Which contains values:
    In [10]: sig = 'WyIxMjguMTk2LjY0LjIxNCIsIll2OUtONXhZTGcxYzdzU2tYQ0trb2x6RnBRayIsIlZkS28yemhidVJpQ3Z6WDZmTnNJRUVWdWcydyJd.CfsDWA.1tUUGb1772CZPn5IlttHM82qiuA'

    In [11]: usts.loads(sig)
    Out[11]:
    [u'128.196.64.214',
    u'Yv9KN5xYLg1c7sSkXCKkolzFpQk',
    u'VdKo2zhbuRiCvzX6fNsIEEVug2w']

    from flask import Flask, request
    test_sig = generate_test_signature('secrets-things-that-arenot-so-secret',
                                       'i-like-the-idea-of-a-salt',
                                       '128.196.64.214',
                                       request)
    """
    usts = URLSafeTimedSerializer(
        signing_secret_key,
        salt=signing_salt)

    signer = Signer(
        fp_secret_key,
        salt=fp_salt)

    client_ip_fingerprint = signer.get_signature(client_ip)

    browser_fingerprint = signer.get_signature(''.join([
        user_agent,
        accept,
        accept_encoding,
        accept_language]))

    sig = usts.dumps([vm_ip, client_ip_fingerprint, browser_fingerprint])
    return sig


def generate_signature_01(conf, request_data):
    client_ip = request_data['client_ip']
    vm_ip = request_data['vm_ip']
    user_agent = request_data['user_agent']
    accept = request_data['accept']
    accept_encoding = request_data['accept_encoding']
    accept_language = request_data['accept_language']

    sig = generate_test_signature(conf['WEB_DESKTOP_SIGNING_SECRET_KEY'],
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


def decode_signature(signing_secret_key, signing_salt, max_age, signature):
    usts = URLSafeTimedSerializer(
        signing_secret_key,
        salt=signing_salt)
    values = usts.loads(signature, return_timestamp=True, max_age=max_age)
    return values


def decode_signature_02(conf, signature):
    values = decode_signature(conf['WEB_DESKTOP_SIGNING_SECRET_KEY'],
                              conf['WEB_DESKTOP_SIGNING_SALT'],
                              conf['MAX_AGE'],
                              signature)

    return values


def validate_fingerprints(fp_secret_key, fp_salt, client_ip_fingerprint, browser_fingerprint, client_ip, user_agent,
                          accept, accept_encoding, accept_language):
    signer = Signer(fp_secret_key, fp_salt)

    calculated_client_ip_fingerprint = signer.get_signature(client_ip)

    calculated_browser_fingerprint = signer.get_signature(''.join([
        user_agent,
        accept,
        accept_encoding,
        accept_language]))

    if calculated_client_ip_fingerprint == client_ip_fingerprint and calculated_browser_fingerprint == browser_fingerprint:
        return True
    else:
        return False


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
    conf.from_pyfile('default_settings.py')
    conf.from_pyfile('local_settings.py')

    test_request_data = dict(
        accept_encoding='Accept-Encoding: gzip, deflate, sdch',
        accept_language='Accept-Language: en-US,en;q=0.8',
        accept='Accept: application/json, text/javascript, */*; q=0.01',
        user_agent='User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36',
        vm_ip='128.196.64.214',
        client_ip='127.0.0.1'
    )

    signature = generate_signature_01(conf, test_request_data)
    print signature
    values, timestamp = decode_signature_02(conf, signature)
    print values
    is_valid = validate_fingerprints_03(conf, values, test_request_data)
    print is_valid
