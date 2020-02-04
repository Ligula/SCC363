import keyboard

print("Welcome to the AAA service menu.")
role = input("Enter your role: ")

#DOCTOR MENU OPTIONS
if(role == 'Doctor' or 'doctor'):
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

#HOSPITAL STAFF MENU OPTIONS
elif(role == 'Staff' or 'staff'):
    print("Your role is " + role)
    print("Press A to search for a patient")
    print("Press B to search for a Doctor")

    ### IF A PRESSED
    # pusername = input("Enter patient username: ")
    # print("Patient username: ")
    # print("Patient forename: ")
    # print("Patient surname: ")
    # print("Patient email address: ")
    # print("Patient conditions: ")

    ### IF B PRESSED
    # dusername = input("Enter doctor username: ")
    # print("Doctor username: ")
    # print("Doctor forename: ")
    # print("Doctor surname: ")
    # print("Doctor email address: ")
    # print("Doctor conditions: ")
    
#PATIENT MENU OPTIONS
elif(role == 'Patient' or 'patient'):
    print("Your role is " + role)
    print("Press A to update username")
    print("Press B to update password")
    print("Press C to update email address")

    ### IF A PRESSED
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

    ### IF B PRESSED
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

    ### IF C PRESSED
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

#REGULATOR MENU OPTIONS
elif(role == 'Regulator' or 'regulator'):
    print("Your role is " + role)
    print("Press A to access audit logs")
    print("Press B to access Doctor data")
    print("Press C to access Staff data")
    print("Press D to assign Doctors to patients")



