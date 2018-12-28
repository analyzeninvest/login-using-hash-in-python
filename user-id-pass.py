#!/usr/bin/env python

def validate_input_username_password(datFile='data.csv', attempts=3):

    """This is a function for validating the username & password. The
    username and password is read from the datFile. The max number of
    tries is defined by the attempts agruments."""    

    from getpass import getpass
    while True:
        print '\n'
        username = raw_input("Username: ")
        password = getpass("Password: ")
        if attempts == 0:
            print("Max number of incorrect username Or password reached.")
            return False
        if validate_from_data_by_field(datFile, username, 'username') and validate_from_data_by_field(datFile, password, 'password'):
            print("Both username & password are correct.")
            return True
        attempts -=1
        print("incorrect username or password, you have " + str(attempts) + " more tries")



def add_new_user(datFile='data.csv', attempts=5):
    
    """This is a function for adding new user and password. The new user
    data is stored in datFile. """
    
    from getpass import getpass
    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    while True:
        if attempts==0:
            print("max numver of attempts reached")
            return False
        username = raw_input("Username: ")
        if validate_from_data_by_field(datFile, username, 'username'):
            print("username already exists, Please pick a different name")
            attempts -= 1
        else:
            password = getpass("Password: ")
            if check_password_rules(password):
                print("Password is obeying password rules.")
                cust_ps = ps.using(salt_size=128, rounds=100000)
                username_hash = cust_ps.hash(username)
                password_hash = cust_ps.hash(password)
                with open(datFile, 'ab') as csv_file:
                    csv_writer = csv.DictWriter(csv_file, fieldnames=['username','password'], lineterminator = '\n')
                    csv_writer.writerow({'username':username_hash, 'password': password_hash})
                    return True
            else:
                print("Password needs to obey the password rules.")
                attempts -=1


def check_password_rules(string):
    """This function checks for password rule in the string. 
    Password rules are:
    1. should be at least 8 char long.
    2. not more than 50.
    3. Should contain at least one digit.
    4. Should contain at least one special character. Special character are to be chosen from following: ?!@#$%^&*.
    5. Should not contain any whitespace.
    6. Should contain some lower case letter.
    7. Should contain some upper case letter.
    """

    import re
    if re.search("[a-z]+",string) and re.search("[A-Z]+",string) and re.search("[0-9]+",string) and re.search("[?!@#$%^&*]+",string) and re.search("[^ \t\n\r\f\v]",string) and (len(string)>8) and (len(string)<50):
        print("Correct input for the password.")
        return True
    else:
        print('Incorrect password\n\nPassword rules are listed below:\n 1. Should be at least 8 char long.\n 2. Not more than 50.\n 3. Should contain at least one digit.\n 4. Should contain at least one special character. Special character are to be chosen from following: ?!@#$%^&*.\n 5. Should not contain any whitespace.\n 6. Should contain some lower case letter.\n 7. Should contain some upper case letter.\n')
        return False
        
    
def validate_from_data_by_field(fileName, string, field):
    """This is a function for validating the field."""

    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    with open(fileName, 'rb') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        for row in csv_reader:
            fieldHash = row[field]
            if ps.verify(string, fieldHash):
                return True

