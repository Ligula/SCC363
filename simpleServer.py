from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask
import ssl, requests

context = ('certificate.pem', 'key.pem')

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/api/v1/login', methods=['POST'])
def login_handler():
    # Check password is correct
    # Provide the user with a one time code via email.
    # Send user to code entry form.
    return "Login handler"

@app.route('/api/v1/otc', method=['POST'])
def otc_handler():
    # One time code handler
    # Check OTC matches the stored OTC
    return "One time code"

@app.route('/api/v1/register', methods=['POST'])
def register_handler():
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
