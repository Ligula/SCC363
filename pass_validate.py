import re 
import sys

def pass_eval(passw, user, dob):

    sys.tracebacklimit=0
    chars = 0
    digits = 0
    spec = 0
    upper = 0

    regex = re.compile('[@_!#£$%^&*()<>?/\|}{~:]') 

    dob = dob.replace("/", "")
    if user in passw:
        raise Exception("Password cannot contain Username!")
    if dob in passw:
        raise Exception("Password cannot contain DOB!")
    # dob = dateofbirth.strip("/")
    #Pseudo pass validation for username / email 

    for c in passw:
        if c.isupper():
            upper+=1
        if c.isalpha():
            chars+=1
        elif c.isdigit():
            digits+=1
        elif regex.search(c):
            spec+=1

    if len(passw) <= 16 and len(passw) >= 8 and chars >= 2 and digits >= 4 and upper >= 1 and spec >= 1:
        return True
    elif len(passw) > 16:
        raise Exception("Password must not exceed 16 characters!")
    elif len(passw) < 8:
        raise Exception("Password not long enough, minimum 8 characters!")
    elif digits < 4:
        raise Exception("Digits must contain 4 digits!")
    elif upper < 1:
        raise Exception("Password must contain one uppercase character!")
    elif spec < 1:
        raise Exception("Password must contain 1 special character!")
    
passw = input("\nEnter password: ")
user = input("\nEnter User")
dob = input("\nEnter DOB e.g. DD/MM/YYYY: ")
while pass_eval(passw, user, dob) != True:
    passw = input("\nEnter password: ")

    
