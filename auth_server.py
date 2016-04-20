from datetime import datetime

from flask import Flask, jsonify

app = Flask(__name__)


@app.route('/')
def current_time_api():
    current_time = datetime.now()
    return jsonify({'current_time': str(current_time)})


if __name__ == '__main__':
    app.run(debug=True, host='192.168.72.19', port=8888)