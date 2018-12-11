import os
import pickle
import atexit
import time
import Crypto.Hash.MD5 as MD5
import json
import requests

host_address = "localhost"
backend_port = 8081
secret = {"blah":"43njaWAJE345902"}

backend_str = "http://{host}:{port}".format(host=host_address, port=backend_port)

class Storage:
    
    def savedata(self):
        response = requests.post("{target}/api/savedata"
        .format(target=backend_str), cookies=secret)
    
    def getlogs(self):
        response = requests.post("{target}/api/getlogs"
        .format(target=backend_str), cookies=secret)
        r = json.loads(response.text)
        l = []
        for i in r.values():
            l.append(i)
        return l
    
    def getUsers(self):
        response = requests.post("{target}/api/userget/all"
        .format(target=backend_str), cookies=secret)
        return response.text

    def logger(self, s): #CHECK
        '''Log data to database'''
        if s == None:
            return True
        response = requests.post("{target}/api/log/{s}"
        .format(target=backend_str, s=s), cookies=secret)
        return True

    def add_answer(self, answer, censusid):
        '''Add answers to database'''
        response = requests.post("{target}/api/newanswer/{censusid}".format(target=backend_str, censusid=censusid), json=answer, cookies=secret)
        if response.text == "False":
            return False
        return True

    def add_user(self, censusid, password, member_type, name, salt):
        ''' Add new user to database'''
        p = {'censusid':censusid, 'password':password, 'member_type':member_type, 'name':name, 'salt':salt}
        response = requests.post("{target}/api/adduser".format(target=backend_str), json=p, cookies=secret)

    def reset_database(self):
        response = requests.post("{target}/api/cleardatabase".format(target=backend_str), cookies=secret)

    def check_census_complete(self, cookie):
        ''' Check if user has completed the census'''
        response = requests.post("{target}/api/censuscheck/{cookie}"
        .format(target=backend_str, cookie=cookie), cookies=secret)
        if response.text == "True":
            return True
        return False


    def get_user_type(self, censusid):
        if censusid == None:
            return None
        response = requests.post("{target}/api/user/{censusid}"
    	.format(target=backend_str, censusid=censusid), cookies=secret)
        if response == "Invalid":
            return None
        return response

    # Verify user's cookie
    def check_cookie(self, cookie):
        if cookie == None:
            return None
        response = requests.post("{target}/api/cookie/{cookie}"
    	.format(target=backend_str, cookie=cookie), cookies=secret)
        if response == "Invalid Cookie":
            return None
        return response.text

    # Check the login credentials
    def check_login(self, censusid, password):
        if len(censusid) < 1 or len(password) < 1:
            return "Incorrect Login!", False, None, None
        response = requests.post("{target}/api/checklogin/{censusid}/{password}"
    	.format(target=backend_str, censusid=censusid, password=password), cookies=secret)
        r = json.loads(response.text)
        if r['login'] is True:
            return "Logged in!", True, r['user_type'], r['cookie']
        return r['err_str'], False, None, None

    # Check user exists
    def check_user_exists(self, censusid):
        response = requests.post("{target}/api/checkuser/{censusid}"
        .format(target=backend_str, censusid=censusid), cookies=secret)
        r = json.loads(response.text)
        return r['result']

    # Retrieve userid from cookie
    def get_censusid(self, cookie):
        response = requests.post("{target}/api/censusid/{cookie}"
        .format(target=backend_str, cookie=cookie), cookies=secret)
        if response.text == "Invalid Cookie":
            return None
        return response.text

    # Remove cookie for logout
    def remove_cookie(self, cookie):
        if cookie != None:
            response = requests.post("{target}/api/logout/{cookie}"
            .format(target=backend_str, cookie=cookie), cookies=secret)

    #Retrieve User info
    def get_user(self, censusid):
        response = requests.post("{target}/api/userget/{censusid}"
        .format(target=backend_str, censusid=censusid), cookies=secret)
        r = json.loads(response.text)
        return r
