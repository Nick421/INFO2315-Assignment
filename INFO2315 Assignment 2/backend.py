from bottle import run, request, post, get, abort
import requests
import os
import pickle
import atexit
import time
import json
from random import choice
from string import ascii_uppercase
import Crypto.Hash.MD5 as MD5
import numpy as np

# Important globals
host = "localhost"
port = "8081"
secret = {"blah":"43njaWAJE345902"}

# Our "Database"
users = {}
cookies = {}
census = []
log = []

# Save data on cleanup
def save_data():
    ''' On cleanup save data to file '''
    try:
        with open("logindata.txt", "wb") as loginFile:
            pickle.dump(users, loginFile)
        with open("censusdata.txt", "wb") as censusFile:
            pickle.dump(census, censusFile)
        with open("logger.log", "wb") as logFile:
            pickle.dump(log, logFile)
        with open("logger.txt", "wb") as logFileBackup:
            pickle.dump(log, logFileBackup)
    except:
        print("Error saving data to file")

# Import login data
try:
    with open("logindata.txt", "rb") as loginFile:
        users = pickle.load(loginFile)
except:
    print("No login file available")
    users = {}
    salt = "sdb%hs2jk3478%"
    salted_password = "teamspace" + salt
    hashed_password = MD5.new(salted_password.encode()).hexdigest()
    users["admin"] = (hashed_password, False, "Administrator", "Administrator", salt)
atexit.register(save_data)

# Import census data
try:
    with open("censusdata.txt", "rb") as censusFile:
        census = pickle.load(censusFile)
except:
    print("No census file available")
    census = []

# Import log data
try:
    with open("logger.log", "rb") as logFile:
        log = pickle.load(logFile)
except:
    print("No log file available")
    log = []


# Helper methods

# Validate front end
def check_connection(cookie):
    if cookie == secret['blah']:
        return True
    return False

## Return a new cookie
def new_cookie(censusid):
    cookie = ''.join(choice(ascii_uppercase) for i in range(90))
    cookies[cookie] = censusid
    return cookie

def mark_census_complete(censusid):
    ''' Mark user as completed the census'''
    if censusid in users:
        users[censusid] = (users[censusid][0], True, users[censusid][2], users[censusid][3], users[censusid][4])
    else:
        print("User doesn't exist")

# API calls
@post('/api/cookie/<cookie:path>')
def validatecookie(cookie):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if cookie in cookies:
        censusid = cookies[cookie]
        # Check if they're an actual user
        if censusid in users:
            # return what level they are
            return users[censusid][2]
    return "Invalid Cookie"

@post('/api/censusid/<cookie:path>')
def get_censusid(cookie):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if cookie in cookies:
        return cookies[cookie]
    return "Invalid Cookie"

@post('/api/censuscheck/<cookie:path>')
def check_census_complete(cookie):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if cookie in cookies:
        censusid = cookies[cookie]
        # Check if they're an actual user
        if censusid in users:
            # return what level they are
            if users[censusid][1] == True:
                return "True"
            return "False"
    return "Invalid Cookie"

@post('/api/checklogin/<censusid:path>/<password:path>')
def check_login(censusid, password):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    login = False
    if censusid not in users:
        err_str = "Incorrect Login"
        return {'err_str':err_str, 'login':login, 'user_type':None, 'cookie':None}
    salted_password = password + users[censusid][4]
    hashed_password = MD5.new(salted_password.encode()).hexdigest()
    if censusid not in users or users[censusid][0] != hashed_password:
        err_str = "Incorrect Login"
        return {'err_str':err_str, 'login':login, 'user_type':None, 'cookie':None}
    user_type = users[censusid][2]
    login_string = "Logged in!"
    cookie = new_cookie(censusid)
    return {'err_str':login_string, 'login':True, 'user_type':user_type, 'cookie':cookie}

@post('/api/log/<s:path>')
def logger(s):
    '''Log data to database'''
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    tmp = time.strftime("%Y-%m-%d %H:%M")
    tmp += " - " + s
    log.append(tmp)

@post('/api/user/<censusid:path>')
def get_user(self, censusid):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if users[censusid] == None:
        return "Invalid"
    return users[censusid][2]

@post('/api/newanswer/<censusid:path>')
def add_answer(censusid):
    '''Add answers to database'''
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if censusid in users:
        if users[censusid][1] == True:
            return "False"
    r = request.json
    b = []
    for value in r.values():
        b.append(value)
    census.append(b)
    mark_census_complete(censusid)
    return "True"

@post('/api/checkuser/<censusid:path>')
def check_user_exists(censusid):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if censusid not in users:
        return {'result':False}
    return {'result':True}

@post('/api/adduser')
def add_user():
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    r = request.json
    users[r['censusid']] = (r['password'], False, r['member_type'], r['name'], r['salt'])

@post('/api/logout/<cookie:path>')
def logout(cookie):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    del cookies[cookie]

@post('/api/userget/<censusid:path>')
def usercheck(censusid):
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    if censusid not in users:
        return {'password':"Error"}
    return {'password':users[censusid][0],'voted':users[censusid][1],'member_type':users[censusid][2],
        'name':users[censusid][3], 'salt':users[censusid][4]}

@post('/api/userget/all')
def usergetall():
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    return users

@post('/api/getlogs')
def usergetlogs():
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    l = {}
    for i in range(0,len(log)):
        l[i] = log[i]
    return l

@post('/api/cleardatabase')
def reset_database():
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    tmp = users["admin"]
    users.clear()
    users["admin"] = tmp
    census.clear()
    
@post('/api/savedata')
def save():
    if (check_connection(request.get_cookie('blah'))) is False:
        abort(401, "Sorry, access denied.")
    save_data()
    header = "gender,dob,home,livedabroad,background,religion,children,english,foreignlanguage"
    np.savetxt('censusdata.csv', census, fmt='%s', delimiter=',', header=header)
    np.savetxt('log.csv', log, fmt='%s', delimiter=',')

# Run the server
run(host=host, port=port)
