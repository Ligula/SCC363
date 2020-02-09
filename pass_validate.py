import re 
import sys
import colorama
from colorama import Fore, Style

def pass_eval(passw, user, dob):

    print(Fore.RED + "")

    sys.tracebacklimit=0
    chars = 0
    digits = 0
    spec = 0
    upper = 0

    regex = re.compile('[@_!#£$%^&*()<>?/\|}{~:]') 
    dob = dob.replace("/", "")

    if user in passw:
        print("\nPassword cannot contain Username!")
        pass
    if dob in passw:
        print("\nPassword cannot contain DOB!")
        pass

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
        print(Fore.WHITE + "")
        return True
    elif len(passw) > 16:
        print("\nPassword must not exceed 16 characters!")
        pass
    elif len(passw) < 8:
        print("\nPassword not long enough, minimum 8 characters!")
        pass
    elif digits < 4:
        print("\nPassword must contain 4 digits!")
        pass
    elif upper < 1:
        print("\nPassword must contain one uppercase character!")
        pass
    elif spec < 1:
        print("\nPassword must contain 1 special character!")
        pass
    
    print(Fore.WHITE + "")

def pass_eval_nousr(passw):

    print(Fore.RED + "")

    sys.tracebacklimit=0
    chars = 0
    digits = 0
    spec = 0
    upper = 0

    regex = re.compile('[@_!#£$%^&*()<>?/\|}{~:]')

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
        print(Fore.WHITE + "")
        return True
    elif len(passw) > 16:
        print("\nPassword must not exceed 16 characters!")
        pass
    elif len(passw) < 8:
        print("\nPassword not long enough, minimum 8 characters!")
        pass
    elif digits < 4:
        print("\nPassword must contain 4 digits!")
        pass
    elif upper < 1:
        print("\nPassword must contain one uppercase character!")
        pass
    elif spec < 1:
        print("\nPassword must contain 1 special character!")
        pass
    
    print(Fore.WHITE + "")

# #user = input("\nEnter User: ")    
# passw = input("\nEnter password: ")
# #dob = input("\nEnter DOB e.g. DD/MM/YYYY: ")

# while pass_eval(passw, user, dob) != True:
#     passw = input("\nEnter password: ")

    
