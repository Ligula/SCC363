from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask, request, Response, jsonify, url_for, redirect
from base64 import b64encode
import ssl, os, hashlib, sys, smtplib, random, uuid, sqlite3
from passlib.hash import argon2
from email.message import EmailMessage
from functools import wraps
from threading import Lock
import time
from datetime import datetime, timedelta
from colorama import Fore, Style

from auditor import Auditor

mutex = Lock()

conn = sqlite3.connect('med.db', check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES)
db = conn.cursor()

auditor = Auditor("audit.log")

db.execute("""CREATE TABLE IF NOT EXISTS account (
Username VARCHAR(255) PRIMARY KEY NOT NULL,
Password VARCHAR(128) NOT NULL,
Email VARCHAR(255) NOT NULL,
Role VARCHAR(255),
PWExpiryDate TIMESTAMP,
VerifyID INT,
Verified BOOLEAN);""")
db.execute("""CREATE TABLE IF NOT EXISTS staff (
Position VARCHAR(255),
DateOfBirth DATE,
FileLocation VARCHAR(255),
StaffUsername VARCHAR(255),
FOREIGN KEY(StaffUsername) REFERENCES account(username));""")
db.execute("""CREATE TABLE IF NOT EXISTS session (
SessionID INT,
IPAddress VARCHAR(255),
Username VARCHAR(255),
StartDate TIMESTAMP,
AuthCode VARCHAR(6),
Valid BOOL,
FOREIGN KEY (Username) REFERENCES account(username));""")
db.execute("""CREATE TABLE IF NOT EXISTS patient (
DateOfBirth DATE,
Conditions VARCHAR(255),
PatientUsername VARCHAR(255),
StaffUsername VARCHAR(255), 
FOREIGN KEY (PatientUsername) REFERENCES account(username),
FOREIGN KEY (StaffUsername) REFERENCES staff(StaffUsername));""")
conn.commit()

db.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(db.fetchall())

def getPasswordExpiryDate(userName):
    mutex.acquire()
    db.execute("SELECT PWExpiryDate FROM account WHERE username=?", (userName,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0] # Row 0, column 0 
    return None

def verifyAccount(verifyId):
    mutex.acquire()
    db.execute("UPDATE account SET Verified=? WHERE VerifyId=?", (True, verifyId,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def addOTC(code, userName):
    mutex.acquire()
    db.execute("UPDATE account SET AuthCode=? WHERE username=?", (code, userName,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def invalidateOTC(userName):
    mutex.acquire()
    db.execute("UPDATE account SET AuthCode=NULL WHERE userName=?", (userName,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def updatePatient(patientUsername, conditions):
    mutex.acquire()
    db.execute("UPDATE patient SET conditions=? WHERE PatientUsername=?", (conditions, patientUsername,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def deleteUser(username):
    mutex.acquire()
    db.execute("DELETE FROM staff WHERE StaffUsername=?", (username,))
    db.execute("DELETE FROM patient WHERE PatientUsername=?", (username,))
    db.execute("DELETE FROM session WHERE username=?", (username,))
    db.execute("DELETE FROM account WHERE username=?", (username,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def updateEmail(username, newEmail):
    mutex.acquire()
    db.execute("UPDATE account SET Email=? WHERE username=?", (newEmail, username,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def updatePassword(username, newPass):
    mutex.acquire()
    db.execute("UPDATE account SET Password=? WHERE username=?", (newPass, username,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def insertSession(ipAddress, username, startTime, authCode):
    mutex.acquire()
    db.execute("INSERT INTO session (IPAddress, Username, StartDate, AuthCode, Valid) VALUES (?, ?, ?, ?, ?)", (ipAddress, username, startTime, authCode, False))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def createUser(username, hpass, email, role, pwExpiry, verifyId):
    mutex.acquire()
    db.execute("INSERT INTO account (Username, Password, Email, Role, PWExpiryDate, VerifyId, Verified) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, hpass, email, role, pwExpiry, verifyId, False),)
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def userExists(username):
    mutex.acquire()
    db.execute("SELECT Username FROM account WHERE Username=?", (username,))
    rows = db.fetchall()
    mutex.release()
    return len(rows) > 0

def getHash(username):
    mutex.acquire()
    db.execute("SELECT Password FROM account WHERE Username=?", (username,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0] # Row 0, column 0
    return None

def accountVerified(username):
    mutex.acquire()
    db.execute("SELECT Verified FROM account WHERE username=?", (username,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0] # Row 0, column 0
    return None

def sessionExists(username, ip):
    mutex.acquire()
    db.execute("SELECT StartDate FROM session WHERE username=? AND IPAddress=?", (username, ip,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0] # Row 0, column 0
    return None

def getEmail(username):
    mutex.acquire()
    db.execute("SELECT Email FROM account WHERE username=?", (username,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0] # Row 0, column 0
    return None

def validateSession(uname, ipAddr, otc):
    mutex.acquire()
    db.execute("UPDATE session SET Valid=True WHERE Username=? AND AuthCode=? AND IPAddress=?", (uname, otc, ipAddr,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def getSessionStartTime(uname, ipAddr):
    mutex.acquire()
    db.execute('SELECT StartDate FROM session WHERE Username=? AND IPAddress=?', (uname, ipAddr,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        print(type(rows[0][0]))
        return rows[0][0]
    return None

def sessionValid(uname, ipAddr):
    mutex.acquire()
    db.execute("SELECT Valid FROM session WHERE Username=? AND IPAddress=?", (uname, ipAddr,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0]
    return None

def deleteSession(uname, ipAddr):
    mutex.acquire()
    db.execute("DELETE FROM session WHERE Username=? AND IPAddress=?", (uname, ipAddr,))
    conn.commit()
    rows = db.rowcount
    mutex.release()
    return rows > 0

def getRole(uname):
    mutex.acquire()
    db.execute("SELECT Role FROM account WHERE username=?", (uname,))
    rows = db.fetchall()
    mutex.release()
    if len(rows) > 0:
        return rows[0][0]
    return None

context = ('certificate.pem', 'key.pem')

# Maximum duration of a session (seconds)
SESSION_TIME = 60 * 60 * 4
PASSWORD_EXPIRE_TIME = 60 * 60 * 24 * 30 # 30 Days

REGULATOR = "regulator"
PATIENT = "patient"
DOCTOR = "doctor"

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
            # Need to check session is valid too (OTC has been entered)
            if sessionExists(user, request.remote_addr) and sessionValid(user, request.remote_addr):
                if getSessionStartTime(user, request.remote_addr) + timedelta(seconds=SESSION_TIME) < datetime.now():
                    deleteSession(user, request.remote_addr)
                    return jsonify({"message" : "Session expired, log back in."})
                return f(*args, **kwargs)
            else:
                # Ask the user to login.
                return jsonify({"message": "You need to login to access this resource"}), 401
        else:
            return jsonify({"message": "Invalid request"}), 400
    return decorated_function

@app.route('/alive')
def alive():
    return 'Alive'

@app.route('/api/v1/user/<uid>', methods=["GET"])
@login_required
def read_user(uid):
    """
        Reads a users information based on their user id.
        Patient can read only their own data.
        Patient can look at some of the doctors details. (name)
        Doctor can only read their own patients data. Maybe blank out address since it isn't needed?
        Regulator can read all
    """
    data = request.get_json()
    if "session" in data:
    
        user = data["session"]["uid"]
        mutex.acquire()
        db.execute('SELECT Role FROM account WHERE Username=?', (user,))
        role=db.fetchone()[0]
        mutex.release()
        
        if(userExists(uid)==False):
            auditor.pushEvent("read_user: %s, doesn't exist" % uid, user, request.remote_addr, "")
            return jsonify({"message": "User doesn't exist"}), 400
        auditor.pushEvent("read_user: %s" % uid, user, request.remote_addr, "")
        #get own data/regulator data (not formatted)
        if(user==uid or role == REGULATOR):
            mutex.acquire()
            db.execute('SELECT Username, Email, Role, Verified FROM account WHERE Username=?', (uid,))
            data = db.fetchone()
            mutex.release()
            response = {}
            response["username"] = data[0]
            response["email"] = data[1]
            response["role"] = data[2]
            response["validated"] = data[3]
            return jsonify(response), 200
        
        if role == PATIENT:
            mutex.acquire()
            db.execute('SELECT StaffUsername FROM patient WHERE PatientUsername=?', (user,))
            staff=db.fetchone()[0]
            mutex.release()
            if(uid == staff):
                mutex.acquire()
                db.execute('SELECT StaffUsername, Position FROM staff WHERE StaffUsername=?', (uid,))
                data = db.fetchone()
                mutex.release()
                return jsonify(data), 200
                
        elif role == DOCTOR:
            mutex.acquire()
            db.execute('SELECT a.Username, a.Email, p.DateOfBirth, p.conditions, p.StaffUsername FROM patient p,account a WHERE p.PatientUsername = a.Username AND a.Username=?', (uid,))
            patient=db.fetchone()
            mutex.release()
            if patient[4]==user:
                return jsonify(patient), 200
        auditor.pushEvent("read_user: %s" % uid, user, request.remote_addr, "Operation denied, invalid role %s" % role)
        return jsonify({"message": "You cannot do this operation"}), 400
        
    return jsonify({"message": "Invalid request"}), 400

@app.route('/api/v1/user/<uid>', methods=["POST"])
@login_required
def update_user(uid):
    """
        Modifies a users details.
        Patient will only be able to modify their own user details.
        Doctors will only be able to modify the patients that are assigned to them
        Regulator can only modify their own details.

        List of possible request formats...
        {
            email: "email@google.com"
        },
        {
            oldPassword: "myPass",
            newPassword: "newPass"
        },
        {
            staffUsername: "user1",
            patientCondition: "there condition" 
        }

    """
    data = request.get_json()
    if "session" in data:
        user = data["session"]["uid"]
        mutex.acquire()
        db.execute('SELECT Role FROM account WHERE Username=?', (user,))
        role=db.fetchone()[0]
        mutex.release()
        
        #get own data/regulator data (not formatted)
        if(user==uid):
            if "email" in data:
                updateEmail(uid,data["email"])
            if "newPassword" in data and "oldPassword" in data:
                if verify_password(data["oldPassword"],getHash(uid)):
                    updatePassword(uid,data["newPassword"])
                    
            auditor.pushEvent("update_user", user, request.remote_addr, "Updated account details: %s" % uid)
            return jsonify({"message": "Personal details updated"}), 200
        else:
            mutex.acquire()
            db.execute('SELECT Role FROM account WHERE Username=?', (uid,))
            if db.rowcount == 0:
                mutex.release()
                return jsonify({"message": "User doesn't exist"}), 400
            subjectRole=db.fetchone()[0]
            mutex.release()
            
            if(subjectRole==PATIENT and role==DOCTOR):
                mutex.acquire()
                db.execute('SELECT StaffUsername FROM patient WHERE PatientUsername = ?', (uid,))
                patient=db.fetchone()
                mutex.release()
                if patient[0]==user:
                    updateString=""
                    if "patientCondition" in data:
                        updateString+="Conditions = \""+data["patientCondition"]+"\""
                    elif "staffUsername" in data:
                        updateString+="StaffUsername = \""+data["staffUsername"]+"\""
                    
                    db.execute('UPDATE patient SET ? WHERE PatientUsername=?', (updateString,uid))
                    conn.commit()
                    auditor.pushEvent("update_user: ", user, request.remote_addr, "Updated account details: %s" % uid)
                    return jsonify({"message": uid+" details updated"}), 200
            
            auditor.pushEvent("update_user", user, request.remote_addr, "Access denied to change: %s" % uid)
            return jsonify({"message": "You cannot change this persons details"}), 400
        
    return jsonify({"message": "Invalid request"}), 400

@app.route('/api/v1/user/<uid>', methods=["DELETE"])
@login_required
def delete_user(uid):
    """
        Deletes a user from the database.
        Patients can only delete themselves.
        Doctors can't delete patients.
        Regulator cannot delete anyone.
    """
    data = request.get_json()
    if "session" in data:
    
        user = data["session"]["uid"]
        
        #get own data/regulator data (not formatted)
        if(user==uid):
        
            db.execute('DELETE FROM patient WHERE PatientUsername=?', (uid,))
                    
            db.execute('DELETE FROM staff WHERE StaffUsername=?', (uid,))
                
            db.execute('DELETE FROM session WHERE Username=?', (uid,))
                
            db.execute('DELETE FROM account WHERE Username=?', (uid,))
            conn.commit()
            auditor.pushEvent("delete_user: %s" % uid, user, request.remote_addr, "")
            return jsonify({"message": "You're account has been removed."}), 200
        else:
            auditor.pushEvent("delete_user: %s" % uid, user, request.remote_addr, "Tried to delete another persons account")
            return jsonify({"message": "You cannot delete someone else"}), 400
        
        
    return jsonify({"message": "Invalid request"}), 400

@app.route('/api/v1/audit', methods=["GET"])
@login_required
def get_audits():
    """
        Only regulator has access to this.
    """
    data = request.get_json()
    if "session" in data:
        user = data["session"]["uid"]
        mutex.acquire()
        db.execute('SELECT Role FROM account WHERE Username=?', (user,))
        role=db.fetchone()[0]
        mutex.release()
        
        #get own data/regulator data (not formatted)
        if(role == REGULATOR):
            auditor.pushEvent("read_audit", user, request.remote_addr, "Access granted")
            return jsonify(auditor.readLogs()), 200
        auditor.pushEvent("read_audit", user, request.remote_addr, "Access denied")
        return "not allowed", 400
        
    return jsonify({"message": "Invalid request"}), 400

@app.route('/api/v1/logout', methods=["GET"])
@login_required
def logout_handler():
    data = request.get_json()
    if deleteSession(data["session"]["uid"], request.remote_addr):
        auditor.pushEvent("logout", data["session"]["uid"], request.remote_addr, "")
        return jsonify({"message": "You've been logged out"}), 200
    else:
        auditor.pushEvent("logout", data["session"]["uid"], request.remote_addr, "No session")
        return jsonify({"message": "No session to logout of."}), 200

@app.route('/api/v1/login', methods=['POST'])
def login_handler():
    data = request.get_json()
    uname = data["username"]
    pwd = data["password"]
    if userExists(uname) == False:
        auditor.pushEvent("login", uname, request.remote_addr, "Account not found")
        return Response("{'message' : 'User doesn't exists'}", status=404)
    else:
        # TODO: check password expiry date.
        if verify_password(pwd, getHash(uname)):
            # Don't allow user to login until their email is verified.
            if accountVerified(uname) == False:
                response = {}
                response["message"] = "Account not verified!"
                auditor.pushEvent("login", uname, request.remote_addr, "Account not verified")
                return jsonify(response), 400
            
            if sessionExists(uname, request.remote_addr):
                    auditor.pushEvent("login", uname, request.remote_addr, "Session already active")
                    return jsonify({'message': 'Account already logged in.'}), 200 #session already verified
            # TODO: Need some session data to send back to the user.
            code = random.randrange(1, 10**6)
            code_str = '{:06}'.format(code)
            # Code from 0000-9999, send to user's email.
            # Start session for the user, needs to be validated first though.
            insertSession(request.remote_addr, uname, datetime.now(), code_str)
            SendEmail(getEmail(uname), 'SCC-363 OTC', 'Login OTC: ' + code_str)
            auditor.pushEvent("login", uname, request.remote_addr, "Sent OTC")
            
            return Response("{'message': 'Login Success!'}", status=200)
    
    auditor.pushEvent("login", uname, request.remote_addr, "Invalid password")
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
    if userExists(user):
        if validateSession(user, request.remote_addr, code) == True or (sessionExists(user, request.remote_addr) and sessionValid(user, request.remote_addr)):
            # Provide user with their role information.
            auditor.pushEvent("otc", user, request.remote_addr, "")
            resp = {}
            resp["message"] = "OTC Correct"
            resp["session"] = {}
            resp["session"]["role"] = getRole(user)
            resp["session"]["uid"] = user

            return jsonify(resp), 200
        else:
            auditor.pushEvent("otc", user, request.remote_addr, "Incorrect OTC")
            return Response("{'message': 'OTC incorrect!'}", status=400)
    else:
        auditor.pushEvent("login", user, request.remote_addr, "No session for OTC")
        return Response("{'message': 'Invalid session'}", status=400)
    return Response("{'message': 'Shouldn't get to here. Internal failure.'}", status=500)

@app.route('/api/v1/verify', methods=['GET'])
def verify_handler():
    vid = request.args.get('verifyId')
    if verifyAccount(vid) == True:
        auditor.pushEvent("verify", vid, request.remote_addr, "")
        return Response("{'message': 'Your account has been verified, you can now login.'}")
    auditor.pushEvent("verify", vid, request.remote_addr, "Unknown verify id")
    return Response("{'message': 'Unknown verify id.'}"), 404

@app.route('/api/v1/register', methods=['POST'])
def register_handler():
    data = request.get_json()
    email = data["email"]
    uname = data["username"]
    pwd = data["password"]
    role = data["role"]

    saltandhash = create_password(pwd)

    if userExists(uname):
        auditor.pushEvent("register", uname, request.remote_addr, "Name taken")
        return Response("{'message':'username taken'}", status=400)
    else:
        vid = generate_random_id()
        # Send link to verify account.
        # 30 day password expiry
        if createUser(uname, saltandhash, email, role, time.time() + PASSWORD_EXPIRE_TIME, vid) == False:
            auditor.pushEvent("register", uname, request.remote_addr, "Name taken")
            return Response("{'message': 'Account name taken!'}", status=200)
        verify_url = "https://localhost:5000" + url_for('verify_handler')+"?verifyId=" + vid
        SendEmail(email, 'SCC-363 Registration', ('Hi %s, welcome to the system! \n Please verify your email at: %s' % (uname, verify_url)))
        auditor.pushEvent("register", uname, request.remote_addr, "")
    return Response("User successfully registered, goto your emails to verify your account.", status=200)


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
    app.run(ssl_context=('cert.pem', 'key.pem'))
