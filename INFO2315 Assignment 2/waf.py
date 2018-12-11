from bottle import run, request, post, get
import re
import string
import array

# Important globals
host = "localhost"
port = "8082"

# Debug mode to check whether or not attacks are working
# Start with it as "True", try the attack, flip it to false, try the attack again and see if your WAF blocked it
# Debug should be set to false when launching the final version
debug = False
# array of potential characters in attacks
attack = ["'", "-", "<", ">", ")", "(", "=",  "/", "#" , "*", "\"", "&", "@", "$", "%" ]

@post('/waf/detect/<string_in:path>')
def detect_attack(string_in):
    if not debug:
        if any(c in attack for c in string_in):
            print("block!")
            return 'False'
        print("all g!")
        return 'True'
    return 'False'

# check censusID if contains uppercase letters and digits
@post('/waf/censusid/<censusid:path>')
def verify_id(censusid):
    if not any(c in string.ascii_uppercase for c in censusid):
        print("block!")
        return "ID must contain uppercase letters"
    return 'True'

# check if the password passes our password policy.
@post('/waf/password/<password:path>')
def verify_password(password):
    if password == "" or len(password) < 8:
        print("block!")
        return "Password is too short"

    if not any(c in string.ascii_lowercase for c in password):
        print("block!")
        return "Password must contain at least one lowercase character"

    if not any(c in string.ascii_uppercase for c in password):
        print("block!")
        return "Password must contain at least one uppercase character"

    return 'True'

# Rather than using paths, you could throw all the requests with form data filled using the
# requests module and extract it here. Alternatively you could use JSON objects.

# Custom definition waf
@post('/waf/custom/field=<field:path>%20test=<test:path>')
def custom_waf(field, test):
    if re.search(test, field) is not None:
        return "True"
    return "False"

# Debug toggle
@post('/waf/debug')
def enable_debugger():
    global debug
    if debug:
        debug = False
    else:
        debug = True

# Run the server
run(host=host, port=port)
