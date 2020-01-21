from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask
import ssl, requests

context = ('certificate.pem', 'key.pem')

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World'





if __name__ == '__main__':
    app.run(ssl_context=context)
