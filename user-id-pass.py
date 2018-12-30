#!/usr/bin/env python

def validate_input_username_password(datFile='data.csv', attempts=3):

    """verify the username and password.
    """

    from getpass import getpass
    while True:
        print '\n'
        username = raw_input("Username: ")
        password = getpass("Password: ")
        if attempts == 0:
            print("Max number of attempts reached.")
            return False
        if validate_from_csv_data_by_field(datFile, username, 'username') and validate_from_csv_data_by_field(datFile, password, 'password'):
            print("both username and password is matching")
            return True
        print("incorrect user name or password, you have " + str(attempts) + " more tries")
        attempts -= 1

def add_new_user(datFile='data.csv', attempts=5):

    """This is a function to add new user. The data will be stored in
    datFile with max number of attempts."""

    from getpass import getpass
    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    while True:

        if attempts == 0:
            print("max number of attempts reached.")
            return False
        username = raw_input("Username: ")
        if validate_from_csv_data_by_field(datFile, username, 'username'):
            print("Username exists, please pick a different username.")
            attempts -= 1
        else:
            password = getpass("Password: ")
            if check_password_rule(password):
                print("Password is obeying the password rules.")
                cust_ps = ps.using(salt_size = 128, rounds = 100000)
                username_hash = cust_ps.hash(username)
                password_hash = cust_ps.hash(password)
                with open(datFile, 'ab') as csv_file:
                    csv_writer = csv.DictWriter(csv_file, fieldnames = ['username', 'password'], lineterminator = '\n')
                    csv_writer.writerow({'username':username_hash, 'password':password_hash})
                    return True
                



def check_password_rule(string):

    """ Password checking using the rules below:
    1. should be at least 8 char long.
    2. should be at most 50 char long.
    3. should have at least one digit.
    4. should have at least upper case char.
    5. should have at least one special cahr.
    6. should contain some lower case char.
    7. should not contain any whitespace.
    """

    import re
    if (len(string)>7) and (len(string)<50) and re.search("[0-9]+",string) and re.search("[A-Z]+",string) and re.search("[!@#$%^&*]",string) and re.search("[a-z]+",string) and re.search("[^ \t\n\r\f\v]",string):
        print("Correct inputs for password given.")
        return True
    else:
        print("Incorrect password entered, Password should follow password rules:\n 1. should be at least 8 char long.\n 2. should be at most 50 char long.\n 3. should have at least one digit.\n 4. should have at least upper case char.\n 5. should have at least one special cahr.\n 6. should contain some lower case char.\n 7. should not contain any whitespace.\n")
        return False
    



def validate_from_csv_data_by_field(fileName, string, field):

    """ Validate string by filed of the fileName.
    """

    from passlib.hash import pbkdf2_sha512 as ps
    import csv
    with open(fileName, 'rb') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter = ',')
        for row in csv_reader:
            fieldHash = row[field]
            if ps.verify(string, fieldHash):
                return True
    
