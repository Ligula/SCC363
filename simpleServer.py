from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask
import ssl, requests
from OpenSSL import SSL

context = SSL.Context(SSL.PROTOCOL_TLSv1_2)
context.use_privatekey_file('server.key')
context.use_certificate_file('server.crt')

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World'





if __name__ == '__main__':
    app.run(ssl_context=context)
