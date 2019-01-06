#!/usr/bin/env python

def validate_input_username_password(datFile = "data.csv", attempts = 3):

    """ validate username and password.
    """

    from passlib.hash import pbkdf2_sha512 as ps
    from getpass import getpass
    while True:
        username = raw_input("Username: ")
        password = getpass("Password: ")
        if attempts == 0:
            print("max number of attempts has been reached.")
            return False
        if validate_from_csv_file_by_filed(datFile, username, 'username') and validate_from_csv_file_by_filed(datFile, password, 'password'):
            print("both username and password are matching.")
            return True
        print("Either username or password is not matching. You have" + str(attempts) + "tries left.")
        attempts -= 1


def add_new_user(datFile = 'data.csv', attempts = 5):

    """ add new user to datFile with some attempts.
    """

    from getpass import getpass
    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    while True:
        if attempts == 0:
            print("max number of attempts has been reached.")
            return False
        username = raw_input("Username: ")
        if validate_from_csv_file_by_filed(datFile, username, 'username'):
            print("username exists, please pick a different user name.")
            attempts -= 1
        else:
            password = getpass("Password: ")
            if check_password_rules(password):
                print("Entered Password Obyeing the password rules.")
                cust_ps = ps.using(salt_size = 128, rounds = 100000)
                username_hash = cust_ps.hash(username)
                password_hash = cust_ps.hash(password)
                with open(datFile, 'ab') as csv_file:
                    csv_writer = csv.DictWriter(csv_file, fieldnames = ['username', 'password'], lineterminator = '\n')
                    csv_writer.writerow({'username':username_hash,'password':password_hash})
                    return True

                
def check_password_rules(string):

    """Password rules:
    1. min length is 8 or more. 
    2. max length is less than 50.
    3. must have some lower case chars.
    4. must have at least one upper case char.
    5. must have a digit.
    6. must have a special char.
    7. must not contain any white space.
    """

    import re
    if (len(string)>7) and (len(string)<50) and re.search("[a-z]+", string) and re.search("[A-Z]+",string) and re.search("[0-9]+",string) and re.search("[!@#$%^&*]+", string) and re.search("[^ \t\n]", string):
        print("Correct input for the password.")
        return True
    else:
        print("Incorrect input for the password, Password rules: \n1. min length is 8 or more. \n2. max length is less than 50. \n3. must have some lower case chars. \n4. must have at least one upper case char. \n5. must have a digit. \n6. must have a special char. \n7. must not contain any white space.")
        return False

def validate_from_csv_file_by_filed(fileName, string, field):

    """ Validate string from filed of the fileName.
    """

    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    with open(fileName, 'rb') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter = ",")
        for row in csv_reader:
            fieldHash = row[field]
            if ps.verify(string, fieldHash):
                return True

    
