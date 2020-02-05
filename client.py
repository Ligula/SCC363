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
  print(r.content)
  if(r.status_code == 200):
    print("Logged iiiiin biiiiitcheeeees")
    otc()


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


def otc():
  user = input('Username: ')
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
  print(r.content)
  print(r.status_code)

def login_menu():
  choice = input("\n1) Login\n2) Register\n> ")

  while choice != "1" and choice != "2":
    print("\nInvalid input, try again!")
    choice = input("1) Login\n2) Register\n> ")
  
  if choice == "1":
    login()
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


  '''
  salt = os.urandom(32)


  data = {
    "id": "empty",
    "username": login,
    "password": password
  }

  hashword = hashlib.sha3_256(password.encode('utf-8')).hexdigest()
  print(hashword)

  jsonData = json.dumps(data)

  print("Well done!")
  '''