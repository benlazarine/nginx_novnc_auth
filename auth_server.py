from urlparse import urlparse, parse_qs

from flask import Flask, request

app = Flask(__name__)


@app.route('/')
def auth():
    original_uri = request.environ.get('HTTP_X_ORIGINAL_URI', '')
    uri_parts = urlparse(original_uri)
    query_string = uri_parts.query
    query_vars = parse_qs(query_string)
    code_list = query_vars.get('code', '401')
    if isinstance(code_list, list):
        code = code_list[0]
    else:
        code = code_list
    return 'Auth result', int(code)


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8888)
