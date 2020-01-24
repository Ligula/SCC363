from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask, request, Response
from base64 import b64encode
import ssl, os, hashlib
from passlib.hash import argon2

context = ('certificate.pem', 'key.pem')

app = Flask(__name__)

def create_password(password):
    # requires passlib & argon2_cffi / argon2pure
    # Passlib uses argon2i
    # More than 2 rounds is recommended, too many takes a long time...
    # https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
    return argon2.using(rounds=5).hash(password)

def verify_password(password, hash):
    return argon2.verify(password, hash)

users = {
    #just for reference
    "testUser": {
        "email": "example@noneofyourbusiness.com",
        # argon2 uses a storage format that has both password and salt together
        # in a specific format.
        # e.g '$argon2i$v=19$m=512,t=4,p=2$eM+ZMyYkpDRGaI3xXmuNcQ$c5DeJg3eb5dskVt1mDdxfw'
        "hash": create_password("testPassword"),
    }
}

@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/alive')
def alive():
    return 'Alive'


@app.route('/test')
def test():
    print(users)
    return 'Done'


@app.route('/api/v1/login', methods=['POST'])
def login_handler():
    data = request.get_json()
    uname = data["username"]
    pwd = data["password"]
    if uname not in users:
        return Response("{'message' : 'User doesn't exists'}", status=404)
    else:
        if verify_password(pwd, users[uname]["hash"]):
            
            # Create one time code, add to user
            # Send email with the code in and ask the user to check their email.
            
            return Response("{'message': 'Password Correct'}", status=200)
            
    return Response("{'message': 'Password Incorrect'}", status=400)


@app.route('/api/v1/otc', methods=['POST'])
def otc_handler():
    data = request.get_json()
    # One time code handler
    # Check OTC matches the stored OTC
    return "One time code"


@app.route('/api/v1/register', methods=['POST'])
def register_handler():
    data = request.get_json()
    email = data["email"]
    uname = data["username"]
    pwd = data["password"]

    saltandhash = create_password(pwd)

    if uname in users:
        return Response("{'message':'username taken'}", status=400)
    else:
        newEntry = {
            uname: {
                "email": email,
                "hash" : saltandhash
            }
        }
        users.update(newEntry)

    return Response("{'message':'User successfully registered'}", status=200)


#def createHash(password):
#    random = os.urandom(32)
#    salt = b64encode(random).decode('utf-8')
#    saltedpwd = password + salt
#    hashword = hasher(saltedpwd.encode('utf-8'))
#    return [salt, hashword]


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
        print('Something went wrong...')
        return False


if __name__ == '__main__':
    app.run(ssl_context=context)
