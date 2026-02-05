from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/quote')
def quote():
    return jsonify({"quote": 999})

if __name__ == '__main__':
    app.run(port=5050)
