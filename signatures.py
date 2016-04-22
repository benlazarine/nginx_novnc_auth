from itsdangerous import URLSafeTimedSerializer, Signer


def generate_signature(signing_secret_key, signing_salt, fp_secret_key, fp_salt, client_ip, vm_ip, user_agent,
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
    test_sig = generate_signature('secrets-things-that-arenot-so-secret',
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


def decode_signature(signing_secret_key, signing_salt, max_age, signature):
    usts = URLSafeTimedSerializer(
        signing_secret_key,
        salt=signing_salt)
    values = usts.loads(signature, return_timestamp=True, max_age=max_age)
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