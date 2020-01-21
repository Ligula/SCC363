from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask
import ssl, requests

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World'




if __name__ == '__main__':
    app.run()