import requests, json, hashlib, sys, os
import pass_validate
import certifi
import urllib3
from colorama import Fore, Style

#Problems:
  # All requests need to have verify=False until certificate verification is added

urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)

serverAddress = 'https://localhost'
serverPort = '5000'
fullAddress = serverAddress + ':' + serverPort



def isServerAlive():
  r = requests.get(fullAddress + '/alive', verify="cert.pem")

  if r.text == "Alive":
    print("\nServer Online")
  return True


def login():
  login = input('\nLogin: ')
  password = input('Password: ')

  data = {
    "username": login,
    "password": password
  }
  jsonData = json.dumps(data)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

  r = requests.post(fullAddress + '/api/v1/login', data=jsonData, headers=headers, verify="cert.pem")

  if(r.status_code == 200 or r.status_code == 302):
    otc(login, r.status_code == 302)
  else:
    print(r.text)
    return False


def register():
  email = input('\nEmail Address: ')
  dob = input("Date of birth i.e. DD/MM/YYYY: ")
  username = input('Username: ')
  password = input('Password: ')
  role = input('Role (patient, doctor, regulator): ').lower()

  while not any(ext in role for ext in ["patient", "doctor", "regulator"]):
    role = input('Role (patient, doctor, regulator): ').lower()

  while pass_validate.pass_eval(password, username, dob) != True:
    password = input("\nPassword: ")

  data = {
    "email": email,
    "username": username,
    "password": password,
    "role": role,
    "dob": dob
  }

  if role == "patient":
    existingConditions = input("Existing conditions: ")
    data["conditions"] = existingConditions
  elif role == "doctor":
    position = input("Position: ")
    data["position"] = position

  jsonData = json.dumps(data)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
  r = requests.post(fullAddress + '/api/v1/register', data=jsonData, headers=headers, verify="cert.pem")
  print(Fore.GREEN + "" + str(r.content.decode('UTF-8')) + Fore.WHITE + "")


def otc(user, alreadyActive):
  code = ''
  if not alreadyActive:
    code = input('Code: ')
  data = {
    "session": {
      "uid": user
    },
    "otc": code
  }
  jsonData = json.dumps(data)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

  r = requests.post(fullAddress + '/api/v1/otc', data=jsonData, headers=headers, verify="cert.pem")
  # print(r.content)
  # print(r.status_code)

  if r.status_code == 200:
    response = json.loads(r.content)
    role = response['session']['role']
    if role == "patient":
      patientMenu(user)
    elif role == "regulator":
      regulatorMenu(user)
    elif role == "doctor":
      doctorMenu(user, role)
  else:
    print(r.text)
    login_menu()


def patientMenu(uid):

  option = ''
  while option != 'E':
    print("\nPress A to view record.")
    print("Press B to update password")
    print("Press C to update email address")
    print("Press D to delete account")
    print("Press E to logout")
    option = ''

    while option != 'A' and option != 'B' and option != 'C' and option != 'D' and option != 'E':
      option = input("Choice: ")

    if option == 'A':
      print("\nFetching record...")
      data = {
        "session": {
          "uid" : uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")
      print(r.status_code)
      print(json.dumps(json.loads(r.content), indent=4, sort_keys=True))

    elif option == 'B':
      oldpwd = input("\nCurrent Password:")
      newpwd = input("New Password: ")
      while pass_validate.pass_eval_nousr(newpwd) != True:
        newpwd = input("New password: ")
      #print("Enter 'cancel' to cancel and return to the menu.")
      newpwdvalid = input("Re-enter new password to confirm: ")
      if newpwd == newpwdvalid:
        data = {
          "session": {
            "uid": uid
          },
          "oldPassword": oldpwd,
          "newPassword": newpwd
        }
        jsonData = json.dumps(data)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

        if r.status_code == 200:
          print("Password updated successfully")

    elif option == 'C':
      newEmail = input("\nNew Email: ")
      data = {
        "session": {
          "uid": uid
        },
        "email": newEmail
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.post(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("Email updated successfully")
        print(r.content)

    elif option == 'D':
      data = {
        "session": {
          "uid": uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.delete(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("\nUser deleted succesfully")

      #debug
      print(r.text)

    elif option == 'E':
      data = {
          "session": {
            "uid": uid
          }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/logout', data=jsonData, headers=headers, verify="cert.pem")
      print(r.text)
      login_menu()

def regulatorMenu(uid):

  option = ''
  while option !='E':
    # TODO: need to allow them to change password / email. Same as patient code.
    print("\nPress A to access audit logs")
    print("Press B to access user data")
    print("Press C to assign Doctors to patients")
    print("Press D to view active sessions")
    print("Press R to revoke session")
    print("Press F to update password")
    print("Press G to update email")
    print("Press L to list users")
    print("Press E to logout")
    option = ''

    while option != 'A' and option != 'B' and option != 'C' and option != 'L' and option != 'D' and option != 'R' and option != 'F' and option != 'G' and option != 'E':
      option = input("Choice: ")

    if option == 'A':
      data = {
        "session": {
          "uid": uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/audit', data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("\nAudit log retreived...")
        print(json.dumps(json.loads(r.content), indent=4, sort_keys=True))
      else:
        print("Failed to get audit log...")

    elif option == 'L':
      data = {
        "session": {
          "uid": uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/userlist', data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("\nUser list retrieved...")
        print(json.dumps(json.loads(r.content), indent=4, sort_keys=True))
      else:
        print("Failed to get user list...")

    elif option == 'B': 
      # Read user
      user = input("\nUsername: ")
      data = {
        "session": {
          "uid": uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/user/' + user, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("User details retreived...")
        print(json.dumps(json.loads(r.content), indent=4, sort_keys=True))
      elif r.status_code == 404:
        print("User not found...")
      else:
        print("Invalid operation")

    elif option == 'C':
      print("\nAssign doctor to patients")

      patient = input("Patient: ")
      doctor = input("Doctor: ")

      data = {
        "session": {
          "uid": uid
        },
        "doctor": doctor,
        "patient": patient
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.post(fullAddress + '/api/v1/assign', data=jsonData, headers=headers, verify="cert.pem")
      print(r.content)
    elif option == 'D': # Active sessions
      print("\nFetching active sessions...")
      data = {
        "session": {
          "uid": uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/sessions', data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print(json.dumps(json.loads(r.content), indent=4, sort_keys=True))
      else:
        print("Invalid operation")

    elif option == 'R':
      print("\nRevoke session")
      username = input('Username: ')
      ip = input('IP: ')
      data = {
        "session": {
          "uid": uid
        },
        "username": username,
        "ip": ip
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.delete(fullAddress + '/api/v1/sessions', data=jsonData, headers=headers, verify="cert.pem")
      if r.status_code == 200:
        print("Session deleted.")
      elif r.status_code == 404:
        print(r.content)
      else:
        print("Invalid operation")

    elif option == 'F':
      oldpwd = input("\nCurrent Password:")
      newpwd = input("New Password: ")
      while pass_validate.pass_eval_nousr(newpwd) != True:
        newpwd = input("\nNew Password: ")
      #print("Enter 'cancel' to cancel and return to the menu.")
      newpwdvalid = input("Re-enter new password to confirm: ")
      if newpwd == newpwdvalid:
        data = {
          "session": {
            "uid": uid
          },
          "oldPassword": oldpwd,
          "newPassword": newpwd
        }
        jsonData = json.dumps(data)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

        if r.status_code == 200:
          print("Password updated successfully")

    elif option == 'G':
      newEmail = input("\nNew Email: ")
      data = {
        "session": {
          "uid": uid
        },
        "email": newEmail
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.post(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("Email updated successfully")
        print(r.content)

    elif option == 'E':
      data = {
          "session": {
            "uid": uid
          }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/logout', data=jsonData, headers=headers, verify="cert.pem")
      print(r.text)
      login_menu()



def doctorMenu(uid, role):
  option = ''

  while option != 'E':
    print("\nPress A to search for a patient")
    print("Press B to update patient condition")
    print("Press C to update email")
    print("Press D to update password")
    print("Press E to logout")
    
    option = input("Choice: ")
    while option != 'A' and option != 'B' and option != 'C' and option != 'D' and option != 'E':
      option = input("Choice: ")

    if option == 'A':
      print("\nView User Data")
      patientuid = input("Enter Patient Username: ")
      data = {
        "session": {
          "uid": uid
        }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/user/' + patientuid, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("\nLoading details...")
        print(json.dumps(json.loads(r.content), indent=4, sort_keys=True))
      elif r.status_code == 404:
        print("\nPatient not found")
    if option == 'B':
      print("Update Patient Details")
      patientid = input("Enter patient username: ")
      condition = input("Conditions:")
      data = {
        "session": {
          "uid": uid
        },
        "patientCondition": condition
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.post(fullAddress + '/api/v1/user/' + patientid, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("Patient details updated successfully")
        print(r.content)
      elif r.status_code == 404:
        print("Patient not found")

    if option == 'C':
      print("Update email")
      newEmail = input("\nNew Email: ")
      data = {
        "session": {
          "uid": uid
        },
        "email": newEmail
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.post(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

      if r.status_code == 200:
        print("Email updated successfully")
        print(r.content)

    if option == 'D':      
      oldpwd = input("\nCurrent Password:")
      newpwd = input("New Password: ")
      while pass_validate.pass_eval_nousr(newpwd) != True:
        newpwd = input("New Password: ")
      #print("Enter 'cancel' to cancel and return to the menu.")
      newpwdvalid = input("Re-enter new password to confirm: ")
      if newpwd == newpwdvalid:
        data = {
          "session": {
            "uid": uid
          },
          "oldPassword": oldpwd,
          "newPassword": newpwd
        }
        jsonData = json.dumps(data)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")

        if r.status_code == 200:
          print("Password updated successfully")
    
    if option == 'E':
      data = {
          "session": {
            "uid": uid
          }
      }
      jsonData = json.dumps(data)
      headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
      r = requests.get(fullAddress + '/api/v1/logout', data=jsonData, headers=headers, verify="cert.pem")
      print(r.text)
      login_menu()


  ### IF A PRESSED
  # pusername = input("Enter patient username: ")
  # print("Patient username: ")
  # print("Patient forename: ")
  # print("Patient surname: ")
  # print("Patient email address: ")
  # print("Patient conditions: ")
  # print("Press B to update patient username")
  # print("Press C to update patient password")
  # print("Press D to update patient email address")
  # print("Press E to update patient condition")

  ### IF B PRESSED
  # newpusername = input("Enter new username: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newpusernamevalid = input("Re-enter new username to confirm: ")
  # if newpusername == newpusernamevalid and
  # if validation requirements are met for new username
  # print("Username updated. Patient has been notified.")
  # if validation requirements for new username are not met
  # elif print("Please enter a new username that meets the validation criteria [INSERT CRITERIA HERE]")
  # newpusername = input("Enter new username: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newpusernamevalid = input("Re-enter new username to confirm: ")
  # if newpusername == newpusernamevalid and
  # print("Username updated. Patient has been notified.")

  ### IF C PRESSED
  # newpwd = input("Enter new password: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newpwdvalid = input("Re-enter new password to confirm: ")
  # if newpwd == newpwdvalid and
  # if validation requirements are met for new password
  # print("Password updated. Patient has been notified.")
  # if validation requirements for new password are not met
  # elif print("Please enter a new password that meets the validation criteria [INSERT CRITERIA HERE]")
  # newpwd = input("Enter new password: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newpwdvalid = input("Re-enter new password to confirm: ")
  # if newpwd == newpwdvalid and
  # print("Password updated. Patient has been notified.")
  
  ### IF D PRESSED
  # newemail = input("Enter new email: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newemailvalid = input("Re-enter new email to confirm: ")
  # if newemail == newemailvalid and
  # if validation requirements are met for new email
  # print("Email updated. Patient has been notified.")
  # if validation requirements for new email are not met
  # elif print("Please enter a new email that meets the validation criteria [INSERT CRITERIA HERE]")
  # newemail = input("Enter new email: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newemailvalid = input("Re-enter new email to confirm: ")
  # if newemail == newemailvalid and
  # print("Email updated. Patient has been notified.")

  ### IF E PRESSED
  # newcondition = input("Enter new condition: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newconditionvalid = input("Re-enter new condition to confirm: ")
  # if newcondition == newconditionvalid and
  # if validation requirements are met for new condition
  # print("Condition updated. Patient has been notified.")
  # if validation requirements for new condition are not met
  # elif print("Please enter a new condition that meets the validation criteria [INSERT CRITERIA HERE]")
  # newcondition = input("Enter new condition: ")
  # print("Enter 'cancel' to cancel and return to the menu.")
  # newconditionvalid = input("Re-enter new condition to confirm: ")
  # if newcondition == newconditionvalid and
  # print("Condition updated/added. Patient has been notified.")

def login_menu():
  choice = input("\n1) Login\n2) Register\n3) Exit\n> ")

  while choice != "1" and choice != "2" and choice != "3":
    print("\nInvalid input, try again!")
    choice = input("1) Login\n2) Register\n3) Exit")
  
  if choice == "1":
    if login() == False:
      login_menu()

  elif choice == "2":
    register()
    login_menu()

  elif choice == "3":
    exit()

if __name__ == "__main__":
  if isServerAlive() == True:
    login_menu()
   

    # login()
    #otc()
    #register()
    #requests.get(fullAddress + '/test', verify="cert.pem")
  else:
    print("Fuck")