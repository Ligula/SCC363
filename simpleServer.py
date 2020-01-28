from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask, request, Response, jsonify, url_for, redirect
from base64 import b64encode
import ssl, os, hashlib, sys, smtplib, random, uuid
from passlib.hash import argon2
from email.message import EmailMessage
from functools import wraps
import time

context = ('certificate.pem', 'key.pem')

# Maximum duration of a session
SESSION_TIME = 60 * 60 * 4

app = Flask(__name__)
app.secret_key = 'some_secret_key_that_needs_to_be_really_long'

def create_password(password):
    # requires passlib & argon2_cffi / argon2pure
    # Passlib uses argon2i
    # More than 2 rounds is recommended, too many takes a long time...
    # https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
    return argon2.using(rounds=5).hash(password)

def verify_password(password, hash):
    return argon2.verify(password, hash)

def generate_random_id():
    return uuid.uuid1().hex

users = {
    #just for reference
    "testUser": {
        "email": "j.p.fletcher@lancaster.ac.uk",
        # argon2 uses a storage format that has both password and salt together
        # in a specific format.
        # e.g '$argon2i$v=19$m=512,t=4,p=2$eM+ZMyYkpDRGaI3xXmuNcQ$c5DeJg3eb5dskVt1mDdxfw'
        "hash": create_password("testPassword"),
        "verified": True,
        # Used for verification link.
        "verify_id": generate_random_id()
    }
}

#list of open sessions
sessions = {
}

def login_required(f):
    """
        Flask decorator for endpoints that require the user to be logged in before
        being able to access the resource.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        if data == None:
            return jsonify({"message": "Invalid request"}), 400
        # Check session exists on both client and server.
        if "session" in data:
            user = data["session"]["uid"]
            if user in sessions:
                if sessions[user]["validated_date"] + SESSION_TIME < time.time():
                    del sessions[user]
                    return jsonify({"message" : "Session expired, log back in."})
                if sessions[user]["ip"] != request.remote_addr:
                    del sessions[user]
                    return jsonify({"message": "IP Changed, re-login is required."}), 401
                return f(*args, **kwargs)
            else:
                # Ask the user to login.
                return jsonify({"message": "You need to login to access this resource"}), 401
        else:
            return jsonify({"message": "Invalid request"}), 400
    return decorated_function

@app.route('/')
@login_required
def hello_world():
    return 'Hello World'


@app.route('/alive')
def alive():
    return 'Alive'


@app.route('/test')
def test():
    print(users)
    return 'Done'

@app.route('/api/v1/user/{uid}')
@login_required
def read_user(uid):
    """
        Reads a users information based on their user id.
        Patient can read only their own data.
        Doctor can only read their own patients data. Maybe blank out address since it isn't needed?
        Regulator can read all
    """
    return "some data"

@app.route('/api/v1/user/{uid}', methods=["UPDATE"])
@login_required
def update_user(uid):
    """
        Modifies a users details.
        Patient will only be able to modify their own user details.
        Doctors will only be able to modify the patients that are assigned to them
        Regulator cannot? modify anything
    """
    return "some data"

@app.route('/api/v1/logout', methods=["GET"])
@login_required
def logout_handler():
    data = request.get_json()
    if data["session"]["uid"] in sessions:
        del sessions[data["session"]["uid"]]
        return jsonify({"message": "You've been logged out"}), 200
    else:
        return jsonify({"message": "No session to logout of."}), 200

@app.route('/api/v1/login', methods=['POST'])
def login_handler():
    data = request.get_json()
    uname = data["username"]
    pwd = data["password"]
    if uname not in users:
        return Response("{'message' : 'User doesn't exists'}", status=404)
    else:
        if verify_password(pwd, users[uname]["hash"]):
            # Don't allow user to login until their email is verified.
            if users[uname]["verified"] == False:
                response = {}
                response["message"] = "Account not verified!"
                return jsonify(response), 400
			
            if uname in sessions:
                session=sessions[uname]
                if(session["ip"]==request.remote_addr):
                    return jsonify(response), 200 #session already verified
            # TODO: Need some session data to send back to the user.
            code = random.randrange(1, 10**4)
            code_str = '{:04}'.format(code)
            # Code from 0000-9999, send to user's email.
            users[uname]["otc"] = code_str
            users[uname]["otc_ip"] = request.remote_addr
            SendEmail(users[uname]["email"], 'SCC-363 OTC', 'Login OTC: ' + code_str)
            
            response = {}
            response["message"] = "Password correct!"
            response["session"] = {}
            response["session"]["uid"] = uname
            return jsonify(response), 200
            
    return Response("{'message': 'Password Incorrect'}", status=400)

@app.route('/api/v1/otc', methods=['POST'])
def otc_handler():
    # One time code handler
    data = request.get_json()
    """
        Expected JSON data format:
        {
            'otc' : '0123',
            'session': {'uid' : 'testUser'}
        }
    """
    code = data["otc"]
    session = data["session"]
    user = session["uid"]
    # Does the user exist?
    if user in users:
        userData = users[user]
        # Check OTC exists and is valid.
        if len(userData["otc"]) != 4:
            return Response("{'message': 'No OTC for user'}", status=400)
        # Check ip matches ip that started the login request.
        if userData["otc_ip"] != request.remote_addr:
            # Blank fields to invalidate otc.
            users[user]["otc"] = ""
            users[user]["otc_ip"] = ""
            return Response("{'message': 'IP changed, session invalidated'}", status=400)
        
        if userData["otc"] == code:
            # TODO: Need to do some other stuff in here too for authenticating user.
            # Allow them into the system since the code is correct.
            # Modify session? Update field in database?
			
			#add session (will be changed to DB)
            uid = session["uid"]
            sessions[uid] = {}
            sessions[uid]["user"]= userData[user]

			#set session ip address to currunt ip (one session per ip)
            sessions[uid]["ip"]= userData["otc_ip"]
			
			#remember time so session can time-out
            sessions[uid]["validated_date"] = time.time()

            # Since the user has entered the correct code, 
            # discard the one time code so it cannot be reused.
            users[user]["otc"] = ""
            users[user]["otc_ip"] = ""
            return Response("{'message': 'OTC correct!'}", status=200)
        else:
            return Response("{'message': 'OTC incorrect!'}", status=200)
    else:
        return Response("{'message': 'Invalid session'}", status=400)
    return Response("{'message': 'Shouldn't get to here. Internal failure.'}", status=500)

@app.route('/api/v1/verify', methods=['GET'])
def verify_handler():
    vid = request.args.get('verifyId')
    for user in users:
        # If the id matches, then verify the user.
        if users[user]["verify_id"] == vid:
            users[user]["verified"] = True
            return Response("{'message': 'Your account has been verified, you can now login.'}")

    return Response("{'message': 'Unknown verify id.'}"), 404

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
                "hash" : saltandhash,
                "verified": False,
                "verify_id": generate_random_id()
            }
        }
        # Send link to verify account.
        verify_url = "https://localhost:5000" + url_for('verify_handler')+"?verifyId=" + newEntry[uname]["verify_id"]
        SendEmail(email, 'SCC-363 Registration', ('Hi %s, welcome to the system! \n Please verify your email at: %s' % (uname, verify_url)))
        users.update(newEntry)

    return Response("{'message':'User successfully registered, goto your emails to verify your account.'}", status=200)


#def createHash(password):
#    random = os.urandom(32)
#    salt = b64encode(random).decode('utf-8')
#    saltedpwd = password + salt
#    hashword = hasher(saltedpwd.encode('utf-8'))
#    return [salt, hashword]


# This account doesn't actually exist yet.
email_user = "scc363.verify@gmail.com"
email_password = "some_magic_password"


def SendEmail(email, subject, body):
    """Sends an email using gmail to an email address
    with a subject and body.
    Returns true or false if sending succeeded or failed. 
    """
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_user
        msg['To'] = email
        msg.set_content(body)
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(email_user, email_password)
        server.send_message(msg)
        server.quit()
        server.close()
        return True
    except:
        e = sys.exc_info()[0]
        print('Something went wrong...', e)
        return False


if __name__ == '__main__':
    app.run(ssl_context=context)
