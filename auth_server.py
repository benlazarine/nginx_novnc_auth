from flask import Flask, request

app = Flask(__name__)


@app.route('/')
def auth():
    # return 'Go away', 401
    return 'All good', 200


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8888)
