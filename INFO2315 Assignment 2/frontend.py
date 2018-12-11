from bottle import route, get, run, post, request, response, redirect, static_file, template
from Crypto import Random
from random import choice
from string import ascii_uppercase
from storage import Storage
import Crypto.Hash.MD5 as MD5
import re
import numpy as np
import time
import csv
import json
import requests

host_address = "localhost"
frontend_port = 8080
backend_port = 8081
waf_port = 8082
secret = {"blah":"43njaWAJE345902"}

waf_str = "http://{host}:{port}".format(host=host_address, port=waf_port)
backend_str = "http://{host}:{port}".format(host=host_address, port=backend_port)

#-----------------------------------------------------------------------------
# This class loads html files from the "template" directory and formats them using Python.
# If you are unsure how this is working, just
class FrameEngine:
    def __init__(this,
        template_path="templates/",
        template_extension=".html",
        **kwargs):
        this.template_path = template_path
        this.template_extension = template_extension
        this.global_renders = kwargs

    def load_template(this, filename):
        path = this.template_path + filename + this.template_extension
        file = open(path, 'r')
        text = ""
        for line in file:
            text+= line
        file.close()
        return text

    def simple_render(this, template, **kwargs):
        template = template.format(**kwargs)
        return  template

    def render(this, template, **kwargs):
        keys = this.global_renders.copy() #Not the best way to do this, but backwards compatible from PEP448, in Python 3.5+ use keys = {**this.global_renters, **kwargs}
        keys.update(kwargs)
        template = this.simple_render(template, **keys)
        return template

    def load_and_render(this, filename, header="header", tailer="tailer", **kwargs):
        template = this.load_template(filename)
        rendered_template = this.render(template, **kwargs)
        rendered_template = this.load_template(header) + rendered_template
        rendered_template = rendered_template + this.load_template(tailer)
        return rendered_template

#-----------------------------------------------------------------------------

# Allow image loading
@route('/img/<picture>')
def serve_pictures(picture):
    return static_file(picture, root='img/')

# Allow CSS
@route('/css/<css>')
def serve_css(css):
    return static_file(css, root='css/')

# Allow javascript
@route('/js/<js>')
def serve_js(js):
    return static_file(js, root='js/')

#-----------------------------------------------------------------------------

# Check new registration details
def add_user(censusid, password, user_type, name): #CHECK
    salt = ''.join(choice(ascii_uppercase) for i in range(12))
    salted_password = password + str(salt)
    hashed_password = MD5.new(salted_password.encode()).hexdigest()
    register = False
    # If censusID not in database then fail
    if database.check_user_exists(censusid) == False:
        err_str = "ID not found. Ask a staff member to check your enrollment"
        return err_str, register
    r = requests.post("{target}/waf/password/{txt}"
                         .format(target=waf_str, txt=password))
    if r.text != "True":
        return r.text, register
    if database.get_user(censusid)['password'] != "":
        err_str = "User has already been registered"
        return err_str, register
    database.add_user(censusid, hashed_password, user_type, name, salt)
    register_string = "Success!"
    register = True
    return register_string, register

# Add blank user
def pre_register(user_type):
    censusid = ''.join(choice(ascii_uppercase) for i in range(12))
    while database.check_user_exists(censusid):
        censusid = ''.join(choice(ascii_uppercase) for i in range(12))
    database.add_user(censusid, "", user_type, "", "")
    return censusid

# Get cookie privileges
def get_privileges():
    cookie = request.get_cookie('user')
    employee_type = database.check_cookie(cookie)
    if employee_type is None or employee_type == "Invalid Cookie":
        return None
    return employee_type

# Load template using library
def load_template(template, header=None, **kwargs):
    if header is not None:
        return fEngine.load_and_render(template, header, **kwargs)
    p = get_privileges()
    if p is None:
    	return fEngine.load_and_render(template, header="header", **kwargs)
    elif p == "Administrator":
        return fEngine.load_and_render(template, header="headeradmin", **kwargs)
    elif p == "Staff":
        return fEngine.load_and_render(template, header="headeradmin", **kwargs)
    elif p == "Researcher":
        return fEngine.load_and_render(template, header="headerresearcher", **kwargs)
    else:
        return fEngine.load_and_render(template, header="headerpublic", **kwargs)
    
# Detect illegal chars
def detect_illegal_chars(text):
    r = requests.post("{target}/waf/detect/{txt}"
                      .format(target=waf_str, txt=text))
    if r.text == "False":
        return True
    return False


#-----------------------------------------------------------------------------
# Redirect to login
@route('/')
@route('/home')
def index():
    return load_template("index")

@route('/api')
def index():
    return load_template("index")

# Display the login page
@get('/login')
def login():
    return load_template("login")

# Logout current user
@get('/logout')
def logout():
    cookie = request.get_cookie('user')
    database.remove_cookie(cookie)
    return load_template("login")

# Display the admin page
@get('/admin')
def admin():
    p = get_privileges()
    if p != None and p == "Administrator":
   	    return load_template("admin")
    else:
        return load_template("login")


# Display users
@get('/userlist')
def userlist():
    r = requests.post("{target}/api/userget/all"
    .format(target=backend_str), cookies=secret)
    res = json.loads(r.text)
    users = res.keys()
    p = get_privileges()
    info = {}
    if p != None and p == "Administrator":
        info = {'title': 'List of Users!',
            'censusids': list(users)
            }
        l = []
        for i in list(users):
            if len(i) != 0 and res[i][2] != "Administrator":
                s = i + " - " + res[i][2]
                l.append(s)
        info = {'title': 'List of Users!',
            'censusids': l
            }
    elif p != None and p == "Staff":
        l = []
        for i in list(users):
            if len(i) != 0 and res[i][2] == "Public":
                s = res[i][3]
                if res[i][1] == True:
                    s += " - Census completed"
                else:
                    s += " - Census not completed"
                l.append(s)
        info = {'title': 'List of Users!',
            'censusids': l
            }
    else:
        return load_template("login")
    return template("templates/userlist", info)

# Display the register page
@get('/register')
def login():
    return load_template("register")

# Display the census questions #TODO
@get('/census')
def census():
    p = get_privileges()
    if p != None and p == "Public":
        if database.check_census_complete(request.get_cookie('user')) == True:
            err_str = "You've already submitted!"
            return load_template("invalid", reason=err_str)
        return load_template("censusquestions")
    else:
        return load_template("login")

# Register a new user
@post('/register')
def do_register():
    censusid = request.forms.get('censusid')
    if detect_illegal_chars(censusid):
        s = "Suspicious text detected"
        database.logger(s)
        return load_template("invalid", reason=s)
    password = request.forms.get('password')
    if detect_illegal_chars(password):
        s = "Suspicious text detected"
        database.logger(s)
        return load_template("invalid", reason=s)
    user_type = request.forms.get('user_type')
    if detect_illegal_chars(user_type):
        s = "Suspicious text detected"
        database.logger(s)
        return load_template("invalid", reason=s)
    name = request.forms.get('name')
    err_str, register = add_user(censusid, password, user_type, name)
    if register:
        s = "Member confirmed registered. Type: " + str(user_type)
        database.logger(s)
        return load_template("success", message=err_str)
    else:
        return load_template("invalid", reason=err_str)


# Admin add a new user
@post('/admin')
def admin_add_user():
    user_type = request.forms.get('user_type')
    if user_type == "Staff":
         return load_template("staffregister")
    censusid = pre_register(user_type)
    mess = "The new user's censusid is: " + str(censusid)
    s = "New user registered. ID: " + str(censusid)
    database.logger(s)
    return fEngine.load_and_render("success", message=mess, header="headeradmin")

# Add new staff member
@post('/staffregister')
def staff_register():
    uname = request.forms.get('name')
    passw = request.forms.get('password')
    p = get_privileges()
    if p != "Administrator":
        return load_template("login")
    censusid = ''.join(choice(ascii_uppercase) for i in range(12))
    while database.check_user_exists(censusid):
        censusid = ''.join(choice(ascii_uppercase) for i in range(12))
    salt = ''.join(choice(ascii_uppercase) for i in range(12))
    salted_password = passw + str(salt)
    hashed_password = MD5.new(salted_password.encode()).hexdigest()
    database.add_user(censusid, hashed_password, "Staff", uname, salt)
    mess = "The new user's censusid is: " + str(censusid)
    return fEngine.load_and_render("success", message=mess, header="headeradmin")

# Attempt the login
# Admin account - censusid: admin, password: teamspace
@post('/login')
def do_login():
    censusid = request.forms.get('username')
    r = requests.post("{target}/waf/censusid/{txt}"
                             .format(target=waf_str, txt=censusid))
    if r.text == "False":
        s = "Suspicious text detected"
        database.logger(s)
        return load_template("invalid", reason=s)
    password = request.forms.get('password')
    r = requests.post("{target}/waf/detect/{txt}"
                             .format(target=waf_str, txt=password))
    if r.text == "False":
        s = "Suspicious text detected"
        database.logger(s)
        return load_template("invalid", reason=s)
    err_str, login, user_type, cookie = database.check_login(censusid, password)
    if login:
        response.set_cookie('user', cookie)
        s = "login successful - " + str(censusid)
        database.logger(s)
        if user_type == "Administrator":
            return load_template("admin", header="headeradmin")
        elif user_type == "Staff":
            return load_template("staff", header="headeradmin")
        elif user_type == "Researcher":
            return load_template("index", header="headerresearcher")
        else:
            return load_template("censusquestions", header="headerpublic")
    else:
        s = "login unsuccessful - " + str(censusid)
        database.logger(s)
        return load_template("invalid", reason=err_str)


@get('/log')
def display_log():
    p = get_privileges()
    info = {}
    if p != None and p == "Administrator":
        info = {'title': 'Log!',
            'censusids': database.getlogs()
            }
        return template("templates/userlist", info)
    else:
        err_str = "You don't have permissions for this page!"
        return load_template("invalid", reason=err_str)

@get('/about')
def about():
    garble = ["leverage agile frameworks to provide a robust synopsis for high level overviews.",
    "iterate approaches to corporate strategy and foster collaborative thinking to further the overall value proposition.",
    "organically grow the holistic world view of disruptive innovation via workplace diversity and empowerment.",
    "bring to the table win-win survival strategies to ensure proactive domination.",
    "ensure the end of the day advancement, a new normal that has evolved from generation X and is on the runway heading towards a streamlined cloud solution.",
    "provide user generated content in real-time will have multiple touchpoints for offshoring."]
    return fEngine.load_and_render("about", garble=np.random.choice(garble))


# Get the staff page
@get('/staff')
def staff():
	p = get_privileges()
	if p != None and p == "Staff":
		return load_template("staff")
	else:
		return load_template("login")

# Clear database
@post('/clear')
def reset_database():
    p = get_privileges()
    if p!= None and p == "Administrator":
        database.reset_database()
        s = "Database cleared by admin"
        database.logger(s)
        return load_template("success", message="Success!")
    s = "Attempted database clear by non-admin"
    database.logger(s)
    return load_template("invalid", reason=s)


# Download csv file
@post('/download')
def send_file():
    p = get_privileges()
    if p!= None and p == "Researcher":
        database.savedata()
        s = "Stats downloaded by researcher"
        database.logger(s)
        return static_file("censusdata.csv", root='', download="Census_data.csv")
    else:
        err_str = "You need to be a researcher!"
        return load_template("invalid", reason=err_str)

# Download log file
@post('/log')
def send_lfile():
    p = get_privileges()
    if p!= None and p == "Administrator":
        database.savedata()
        s = "Log file downloaded"
        database.logger(s)
        return static_file("log.csv", root='', download="log.csv")
    else:
        err_str = "You need to be a researcher!"
        return load_template("invalid", reason=err_str)

# Researcher sees the number of responses
@get('/researcher')
def researcher():
    p = get_privileges()
    if p!= None and p == "Researcher":
        r = requests.post("{target}/api/userget/all".format(target=backend_str), cookies=secret)
        res = json.loads(r.text)
        users = res.keys()
        responses = 0
        total = 0
        m = ""
        for i in list(users):
            if res[i][1] == True:
                responses = responses + 1
            if res[i][2] == "Public":
                total = total + 1
            m = "Received census responses: " + str(responses) + "/" + str(total)
        return load_template("researcher", message=m)

@post('/censusquestions')
def process_answers():
    cookie = request.get_cookie('user')
    if cookie == None or database.get_censusid(cookie) is None:
        return load_template("login")
    censusid = database.get_censusid(cookie)
    if database.check_census_complete(censusid) == True:
        err_str = "You've already submitted!"
        return load_template("invalid", reason=err_str)
    res = {}
    res['a1'] = request.forms.get('answerOne')
    res['a2'] = request.forms.get('answerTwo')
    res['a3'] = request.forms.get('answerThree')
    res['a4'] = request.forms.get('answerFour')
    res['a5'] = request.forms.get('answerFive')
    res['a6'] = request.forms.get('answerSix')
    res['a7'] = request.forms.get('answerSeven')
    res['a8'] = request.forms.get('answerEight')
    res['a9'] = request.forms.get('answerNine')
    res['a10'] = request.forms.get('answerTen')
    res['a11'] = request.forms.get('answerEleven')
    for i in res.values():
        if detect_illegal_chars(i):
            s = "Suspicious text in census detected"
            database.logger(s)
            return load_template("invalid", reason=s)
    if database.add_answer(res, censusid) == False:
        err_str = "Didn't submit!"
        return load_template("invalid", reason=err_str)
    s = "Census completed by: " + str(censusid)
    database.logger(s)
    return load_template("success", message="Success!")


#-----------------------------------------------------------------------------
fEngine = FrameEngine()
database = Storage()
run(host=host_address, port=frontend_port, debug=True)
