import requests, json, hashlib, sys, os

#Problems:
  # All requests need to have verify=False until certificate verification is added


serverAddress = 'https://127.0.0.1'
serverPort = '5000'
fullAddress = serverAddress + ':' + serverPort



def isServerAlive():
  r = requests.get(fullAddress + '/alive', verify=False)
  if r.text == "Alive":
    print("Server Online")
  return True


def login():
  login = input('Login: ')
  password = input('Password: ')

  data = {
    "username": login,
    "password": password
  }
  jsonData = json.dumps(data)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

  r = requests.post(fullAddress + '/api/v1/login', data=jsonData, headers=headers, verify=False)
  if(r.status_code == 200):
    print("Logged iiiiin biiiiitcheeeees")
  print(r.content)


def register():
  email = input('Email Address: ')
  username = input('Username: ')
  password = input('Password: ')

  data = {
    "email": email,
    "username": username,
    "password": password
  }
  jsonData = json.dumps(data)
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

  r = requests.post(fullAddress + '/api/v1/register', data=jsonData, headers=headers, verify=False)
  print(r.status_code)




if isServerAlive() == True:
  print("Yahoo!")
  login()
  #register()
  #requests.get(fullAddress + '/test', verify=False)
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