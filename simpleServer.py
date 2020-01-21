from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask
import ssl, requests

context = ('certificate.pem', 'key.pem')

app = Flask(__name__)

users = dict()

@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/api/v1/login', methods=['POST'])
def login_handler():
    data = request.get_json()
    uname = data["username"]
    pwd = data["password"]
    hashpwd = hash(pwd)
    if uname in users:
        # Check password is valid
        # Hash password on the server
        # If the password is correct, send one-time code and store one-time code for testing
        return {'message': 'You have logged in'}, status.HTTP_200_OK
    else:
        return {'message' : "User doesn't exists"}, status.HTTP_404_NOT_FOUND
    return "Login handler"

@app.route('/api/v1/otc', method=['POST'])
def otc_handler():
    data = request.get_json()
    # One time code handler
    # Check OTC matches the stored OTC
    return "One time code"

@app.route('/api/v1/register', methods=['POST'])
def register_handler():
    data = request.get_json()
    return "Register handler"

# This account doesn't actually exist yet.
email_user = "scc363-verify@gmail.com"
email_password = "some_magic_password"

def SendEmail(email, subject, body):
    """Sends an email using gmail to an email address
    with a subject and body.
    Returns true or false if sending succeeded or failed. 
    """
    try:
        to = [email]
        email_text = """\
        From: %s
        To: %s
        Subject: %s

        %s
        """ % (email_us, ", ".join(to), subject, body)
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(email_user, email_password)
        server.sendmail(email_user, to, email_text)
        server.close()
        return True
    except:
        print 'Something went wrong...'
        return False

if __name__ == '__main__':
    app.run(ssl_context=context)
