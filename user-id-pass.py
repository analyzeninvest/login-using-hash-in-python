#!/usr/bin/env python

def validate_input_username_password(datFile="data.csv", attempts=3):

    """validate the username & password.
    """

    from getpass import getpass
    while True:
        print("\n")
        username = raw_input("Username: ")
        password = getpass("Password: ")
        if attempts == 0:
            print("max number of attempts reached.")
            return False
        if validate_from_csv_file_by_filed(datFile,username,'username') and validate_from_csv_file_by_filed(datFile,password,'password'):
            print("both username and password is matching.")
            return True
        print("incorrect username and password, you have " + str(attempts) + " attempts left.")
        attempts -= 1

def add_new_user(datFile='data.csv', attempts=5):

    """ This function will add new user.
    """

    from getpass import getpass
    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    while True:
        if attempts == 0:
            print("max number of attempts reached.")
            return False
        username = raw_input("Username : ")
        if validate_from_csv_file_by_filed(datFile, username, 'username'):
            print("Username exists, please pick a different one.")
            attempts -= 1
        else:
            password = getpass("Password: ")
            if check_password_rules(password):
                print("Password is obeying the password rules.")
                cust_ps = ps.using(salt_size = 128, rounds = 100000)
                username_hash = cust_ps.hash(username)
                password_hash = cust_ps.hash(password)
                with open(datFile, 'ab') as csv_file:
                    csv_writer = csv.DictWriter(csv_file, fieldnames = ['username', 'password'], lineterminator = '\n' )
                    csv_writer.writerow({'username':username_hash, 'password':password_hash})
                    return True

def check_password_rules(string):

    """Password Rules:
    1. must be at least 8 chars.
    2. must be at most 50 chars.
    3. should have some lower case chars.
    4. should have one upper case char.
    5. should have a digit.
    6. should have a special char.
    7. should not have any white spaces.
    """

    import re
    if (len(string)>7) and (len(string)<50) and re.search("[a-z]+",string) and re.search("[A-Z]+",string) and re.search("[0-9]+",string) and re.search("[!@#$%^&*]+",string) and re.search("[^ \t\n]", string):
        print("Input password is correct")
        return True
    else:
        print("Input password needs to meet password rules:\n 1. must be at least 8 chars.\n 2. must be at most 50 chars.\n 3. should have some lower case chars.\n 4. should have one upper case char.\n 5. should have a digit.\n 6. should have a special char.\n 7. should not have any white spaces.\n")
        return False
    
def validate_from_csv_file_by_filed(fileName, string, field):

    """validate hashes by filed from fileName
    """

    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    with open(fileName, 'rb') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        for row in csv_reader:
            fieldHash = row[field]
            if ps.verify(string, fieldHash):
                return True
    

