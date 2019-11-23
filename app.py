#!/usr/bin/env python3

# Imports
from flask import Flask, request, render_template, redirect, Response, abort, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import random
import math


# Define Flask App
global app
app = Flask(__name__)
app.debug = False
# This line is for Sean's development system, you may need to use the line commented below it
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users//sean_local//PycharmProjects//pwd_gen_ent_calc//test.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'


# Define SQLAlchemy Database Object
global db
db = SQLAlchemy(app)


# Define Flask Login Manager to Handle User Authentication and Access
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# SQLAlchemy Database Model for an App User
class AppUser(db.Model):
    id = db.Column(db.Integer,
                   primary_key=True)

    username = db.Column(db.String(80),
                         unique=True,
                         nullable=False)

    email = db.Column(db.String(120),
                      unique=True,
                      nullable=False)

    password = db.Column(db.String(120),
                         unique=True,
                         nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


# SQLAlchemy Database Model for a stored password
class StoredPassword(db.Model):
    id = db.Column(db.Integer,
                   primary_key=True)

    acctlocation = db.Column(db.String(120),
                             nullable=False)

    password = db.Column(db.String(120),
                         nullable=False)

    username = db.Column(db.String(120),
                         nullable=False)

    userid = db.Column(db.Integer,
                       nullable=False)

    def __repr__(self):
        return "%d" % self.id


# Flask-login User Object
class User(UserMixin):

    def __init__(self, id):
        curruser = AppUser.query.filter_by(id=id).first()
        self.id = id
        self.name = curruser.username
        self.password = curruser.password

    def __repr__(self):
        return "%s" % self.name


# build the list of possible characters used in random password generation given the users input
def buildCharSet(lower, upper, number, special):
    charlist = []
    # lowercase letters
    if lower:
        for lletter in "abcdefghijklmnopqrstuvwxyz":
            charlist.append(lletter)
    # uppercase letters
    if upper:
        for uletter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            charlist.append(uletter)
    # numbers
    if number:
        for number in "0123456789":
            charlist.append(number)
    # special characters
    if special:
        for specchar in "!@#$%^&*,./(){}[|`~<>;:=+-_?":
            charlist.append(specchar)

    return charlist


def password(length=12, charlist=[]):
    password = []
    for x in range(0, length):
        charnum = random.randint(0, len(charlist) - 1)
        password.append(charlist[charnum])
    return "".join(password)


# Function to determine if the input string contains numbers
def hasNumber(inputStr):
    return any(char.isdigit() for char in inputStr)


# Function to determine if the input string contains lowercase letters
def hasLower(inputStr):
    return any(char.islower() for char in inputStr)


# Function to determine if the input string contains uppercase letters
def hasUpper(inputStr):
    return any(char.isupper() for char in inputStr)


# Function to determine if the input string contains special characters
def hasSpec(inputStr):
    return any(char in "!@#$%^&*,./~`'\"[]{}()=+\\|;:<>-_?" for char in inputStr)


# Function to calculate password entropy
def entropyCalc(password):
    formula = """E = log2(R^L)
        where:
            E = password entropy
            R = pool of unique characters
            L = number of characters in your password
            R^L = the number of possible passwords
            log2(R^L) = the number of bits of entropy
    """
    # Calculate the number of possible unique characters that could've been used in the password
    poolOfChars = 0
    if hasLower(password):
        poolOfChars += 26
    if hasUpper(password):
        poolOfChars += 26
    if hasNumber(password):
        poolOfChars += 10
    if hasSpec(password):
        poolOfChars += 32

    # Calculate the number of possible passwords given the list of unique characters
    rToL = pow(poolOfChars, len(password))

    # Calculate the password Entropy
    entropy = math.log2(rToL)
    return entropy


# Home Page URL Route and Home Page View Function
@app.route('/')
def home_page():
    if current_user.is_authenticated:
        return render_template('base.html', title="Home", displayLogonForm=False, name=current_user.name)
    else:
        return render_template('base.html', title="Home", displayLogonForm=True)


# User Registration URL Route and User Registration View Function
@app.route('/user_register', methods=["GET", "POST"])
def user_register():
    # If the user has submitted data for User Registration
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        # Create User with SQLAlchemy
        newuser = AppUser(username=username, password=password, email=email)
        db.session.add(newuser)
        db.session.commit()
        # Render page showing successful user registration and logon form
        return render_template('base.html', title="User Registration", displayLogonForm=True,
                               message="User Created Successfully", displayUserRegisterForm=False)

    # If an unauthenticated user navigates to the User Registration Page
    else:
        return render_template('base.html', title="User Registration", displayLogonForm=False,
                               displayUserRegisterForm=True)


# Login URL Route and Login View Function
@app.route('/login', methods=["GET", "POST"])
def login():
    # If login form was submitted, process user login
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Query users from AppUser Model
        qusers = AppUser.query.filter_by(username=username)
        # iterate through the queried users
        for myuser in qusers:
            # if the submitted user equals the queried username
            if username == myuser.username:
                # if the submitted password equals the queried password
                if password == myuser.password:
                    # create login manager user object
                    tmp_user = User(myuser.id)
                    # log user in
                    login_user(tmp_user)
                    # grab next argument to clear buffer
                    next = request.args.get('next')
                    # redirect to user home page
                    return redirect(url_for('home_page'))
                else:
                    # If the password doesn't match the DB version, abort login
                    return abort(401)
            else:
                # If the username doesn't match the DB records, abort login
                return abort(401)
    # If login form was submitted but user browses to Login Page
    elif request.method == 'GET':
        # If user is authenticated, do not display logon form
        if current_user.is_authenticated:
            return render_template('base.html', title="User Login", displayLogonForm=False, name=current_user.name)

        # If user is not authenticated, display logon form
        else:
            return render_template('base.html', title="User Login", displayLogonForm=True)


# Password Generation URL Route and Password Generation View Function
@app.route('/pwd-gen', methods=["GET", "POST"])
# Login Required to reach this URL Route
@login_required
def password_generation():
    # Initialize function variables
    genpass = ""
    passent = 0
    thislower, thisupper, thisnumber, thisspec = False, False, False, False

    # if the request method was a post meaning there was user submission
    if request.method == 'POST':
        # Set all the variables based on user input
        if request.form['length']:
            thislength = int(request.form["length"])
        else:
            thislength = 12
        if 'lowers' in request.form:
            thislower = True
        if 'uppers' in request.form:
            thisupper = True
        if 'numbers' in request.form:
            thisnumber = True
        if 'specials' in request.form:
            thisspec = True

        # build the charlist to use for password generation
        charlist = buildCharSet(thislower, thisupper, thisnumber, thisspec)
        # generate the password based ont he charlist and length
        genpass = password(thislength, charlist)
        # calculate entropy of the generated password
        passent = "%.0f" % entropyCalc(genpass)

    return render_template('password-generation.html', title="Password Generation", displayLogonForm=False,
                           name=current_user.name, generated_password=genpass,
                           generated_password_entropy=passent)


# Password Entropy Calculator URL Route and Password Entropy Calculator View Function
@app.route('/pwd-calc', methods=["GET", "POST"])
# Login Required to reach this URL Route
@login_required
def password_entropy_calculator():
    # Initialize function variables
    subpass = ""
    subpassent = 0

    # If the request method is a post meaning the user submitted data
    if request.method == 'POST':
        if 'subpass' in request.form:
            subpass = request.form["subpass"]
            # Calculate Entropy of the submitted password
            subpassent = "%.0f" % entropyCalc(request.form['subpass'])

    return render_template('password-entropy-calculator.html', title="Password Entropy Calculator",
                           displayLogonForm=False, name=current_user.name, submitted_password=subpass,
                           submitted_password_entropy=subpassent)


# Password Storage URL Route and Password Storage View Function
@app.route('/pwd-store')
# Login Required to reach this URL Route
@login_required
def password_storage():
    passwordList = []

    # Query passwords from the store passwords model based on the logged in userid
    thesePasswords = StoredPassword.query.filter_by(userid=current_user.id).all()

    # Iterate thru the queried passwords
    for thisPassword in thesePasswords:
        # Append the password and required data to a list
        passwordList.append([thisPassword.acctlocation, thisPassword.username, thisPassword.password])

    return render_template('password-storage.html', title="Password Storage", displayLogonForm=False,
                           name=current_user.name, passwords=passwordList)


# User Logout URL Route and User Logout View Function
@app.route('/logout')
# Login Required to reach this URL Route
@login_required
def logout():
    logout_user()
    return render_template('base.html', title="User Logout", messsage="User Logged out Successfully", displayLogonForm=True)


# Login Manager load_user Definition
@login_manager.user_loader
def load_user(userid):
    return User(userid)


# If application was executed and not imported, start app
if __name__ == '__main__':
    app.run(debug=True)
