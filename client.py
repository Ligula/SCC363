import requests, json, hashlib, sys

#Steps:
#


login = input('Login: ')
password = input('Password: ')


data = {
  "username": login,
  "password": password
}

hashword = hashlib.sha3_256(password.encode('utf-8')).hexdigest()
print(hashword)

jsonData = json.dumps(data)




print("Well done!")