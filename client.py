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

  if(r.status_code == 200):
    otc(login)
  else:
    return False


def register():
  email = input('\nEmail Address: ')
  dob = input("Date of birth i.e. DD/MM/YYYY: ")
  username = input('Username: ')
  password = input('Password: ')
  role = input('Role (patient, doctor, regulator): ').lower()

  while pass_validate.pass_eval(password, username, dob) != True:
    password = input("\nPassword: ")


  data = {
    "email": email,
    "username": username,
    "password": password,
    "role": role
  }
  jsonData = json.dumps(data)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
  r = requests.post(fullAddress + '/api/v1/register', data=jsonData, headers=headers, verify="cert.pem")
  print(Fore.GREEN + "" + str(r.content.decode('UTF-8')) + Fore.WHITE + "")


def otc(user):
  code = input('Code: ')
  data = {
    "session": {
      "uid": user
    },
    "otc": code
  }
  jsonData = json.dumps(data)
  print(jsonData)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

  r = requests.post(fullAddress + '/api/v1/otc', data=jsonData, headers=headers, verify="cert.pem")
  print(r.content)
  print(r.status_code)

  if r.status_code == 200:
    response = json.loads(r.content)
    role = response["session"]["role"]
    if role == "patient":
      patientMenu(user)
    elif role == "regulator":
      regulatorMenu(user)
    elif role == "doctor":
      doctorMenu(user)

def patientMenu(uid):
  print("Press A to view record.")
  print("Press B to update password")
  print("Press C to update email address")
  print("Press D to delete account")
  option = 'E'

  while option != 'A' and option != 'B' and option != 'C' and option != 'D':
    option = input("Choice: ")
  if option == 'A':
    print("Fetching record...")
    data = {
      "session": {
        "uid" : uid
      }
    }
    jsonData = json.dumps(data)
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    r = requests.get(fullAddress + '/api/v1/user/' + uid, data=jsonData, headers=headers, verify="cert.pem")
    print(r.status_code)
    print(r.content)
  elif option == 'B':
    oldpwd = input("\nCurrent Password:")
    newpwd = input("\nPassword: ")
    while pass_validate.pass_eval_nousr(newpwd) != True:
      newpwd = input("\nPassword: ")
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
      print(r)
    #if newpwd == newpwdvalid and
    #if validation requirements are met for new password
    #print("Password updated. Patient has been notified.")
    #if validation requirements for new password are not met
    #elif print("Please enter a new password that meets the validation criteria [INSERT CRITERIA HERE]")
    #newpwd = input("Enter new password: ")
    #print("Enter 'cancel' to cancel and return to the menu.")
    #newpwdvalid = input("Re-enter new password to confirm: ")
    #if newpwd == newpwdvalid and
    #print("Password updated. Patient has been notified.")
    print("Do something...")
  elif option == 'C':
    #newemail = input("Enter new email: ")
    #print("Enter 'cancel' to cancel and return to the menu.")
    #newemailvalid = input("Re-enter new email to confirm: ")
    #if newemail == newemailvalid and
    #if validation requirements are met for new email
    #print("Email updated. Patient has been notified.")
    #if validation requirements for new email are not met
    #elif print("Please enter a new email that meets the validation criteria [INSERT CRITERIA HERE]")
    #newemail = input("Enter new email: ")
    #print("Enter 'cancel' to cancel and return to the menu.")
    #newemailvalid = input("Re-enter new email to confirm: ")
    #if newemail == newemailvalid and
    #print("Email updated. Patient has been notified.")
    print("Do something...")
  elif option == 'D':
    print("Do something...")

def regulatorMenu(uid):
  print("Press A to access audit logs")
  print("Press B to access Doctor data")
  print("Press C to access Staff data")
  print("Press D to assign Doctors to patients")

def doctorMenu(uid):
  print("Your role is " + role)
  print("Press A to search for a patient")

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
  choice = input("\n1) Login\n2) Register\n> ")

  while choice != "1" and choice != "2":
    print("\nInvalid input, try again!")
    choice = input("1) Login\n2) Register\n> ")
  
  if choice == "1":
    if login() == False:
      login_menu()
  elif choice == "2":
    register()
    login_menu()

if __name__ == "__main__":
  if isServerAlive() == True:
    login_menu()
   

    # login()
    #otc()
    #register()
    #requests.get(fullAddress + '/test', verify="cert.pem")
  else:
    print("Fuck")