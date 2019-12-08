#!/usr/bin/env python3

# Imports
from flask import Flask, request, render_template, redirect, Response, abort, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import random
import math
import hashlib
from cryptography.fernet import Fernet

# Define Flask App
global app
app = Flask(__name__, template_folder="templates")
app.debug = False
# This line is for Sean's development system, you may need to use the line commented below it
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users//sean_local//PycharmProjects//pwd_gen_ent_calc//test.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'

# Salt for password hashes
global salt
salt = '10@(83'
# Encryption key for password storage encryption and decryption
global key
key = b'VM4oCt3lOj-d0-6lPcrH_-TqlOpfB86PGnGAmINgw2o='

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

    phash = db.Column(db.String(120),
                         unique=True,
                         nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


# SQLAlchemy Database Model for a stored password
class StoredPassword(db.Model):
    id = db.Column(db.Integer,
                   primary_key=True)

    acctlocation = db.Column(db.String(120),
                             nullable=False,
                             unique=False)

    password = db.Column(db.String(120),
                         nullable=False,
                         unique=False)

    username = db.Column(db.String(120),
                         nullable=False,
                         unique=False)

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
        self.phash = curruser.phash

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


# create random password based on the charlist
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


# Function to identify password strength based on password entropy
def passwordStrength(passwordEntropy):
    if passwordEntropy >= 128:
        return "verystrong"
    elif passwordEntropy >= 60:
        return "strong"
    elif passwordEntropy >= 36:
        return "reasonable"
    elif passwordEntropy >= 28:
        return "weak"
    else:
        return "veryweak"


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
    failedUserCreation = False
    if request.method == 'POST':
        # Ensure the user has submitted a username that is not an empty string
        if ('username' in request.form) and (request.form['username'] != ""):
            username = request.form['username']
        else:
            failedUserCreation = True

        # Ensure the user has submitted a password that is not an empty string
        if ('password' in request.form) and (request.form['password'] != ""):
            password = request.form['password']
            tobehashed = password+salt
            passwordHash = hashlib.md5(tobehashed.encode()).hexdigest()
        else:
            failedUserCreation = True

        # Ensure the user submitted an email address that is not an empty string
        if('email' in request.form) and (request.form['email'] != ""):
            email = request.form['email']
        else:
            failedUserCreation = True

        # Render a failed user creation page if the appropriate items were not submitted
        if failedUserCreation:
            return render_template('base.html', title="User Registration", displayLogonForm=False,
                               message="User Creation Failed", displayUserRegisterForm=True)
        # Create the user if no issues were found during submission
        else:
            # Create User with SQLAlchemy
            newuser = AppUser(username=username, phash=passwordHash, email=email)
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
        # compute password salted hash with for verification against stored salted hash
        tobehashed = password+salt
        passwordHash = hashlib.md5(tobehashed.encode()).hexdigest()
        # Query users from AppUser Model
        qusers = AppUser.query.filter_by(username=username)
        # iterate through the queried users
        for myuser in qusers:
            # if the submitted user equals the queried username
            if username == myuser.username:
                # if the submitted password hash equals the queried password hash
                if passwordHash == myuser.phash:
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
    return abort(401)


# User-Management URL Route and User-Management View Function
@app.route('/user-management', methods=["GET", "POST"])
# Login Required to reach this URL Route
@login_required
def user_management():

    thisUser = AppUser.query.filter_by(id=current_user.id).first()
    tmpUser = {}
    passwordChangeFail = False
    userChangesApplied = False
    # If the user posted forms
    if request.method == "POST":
        # if the user posted changes to their user account
        if 'userchange' in request.form:
            # Check for changes to username and ensure their username is not an empty string
            if (request.form['username'] != thisUser.username) and (request.form['username'] != ''):
                thisUser.username = request.form['username']
                userChangesApplied = True
            # Check for changes to email and ensure their email address is not an empty string
            if (request.form['email'] != thisUser.email) and (request.form['email'] != ''):
                thisUser.email = request.form['email']
                userChangesApplied = True
            # Check for a null new password
            if request.form['newpassword'] != "":
                tobehashed = request.form['currentpassword'] + salt
                passwordHash = hashlib.md5(tobehashed.encode()).hexdigest()
                # check to ensure the new password hash and the old password hash are not the same
                if passwordHash == thisUser.phash:
                    # check that the newpassword and confirmed newpassword are the same
                    if request.form['newpassword'] == request.form['newpasswordconfirm']:
                        tobehashed = request.form['newpassword'] + salt
                        passwordHash = hashlib.md5(tobehashed.encode()).hexdigest()
                        thisUser.phash = passwordHash
                        userChangesApplied = True
                    else:
                        passwordChangeFail = True
                        userChangesApplied = False
                else:
                    passwordChangeFail = True
                    userChangesApplied = False
        # If the user requested account deletion
        if 'userdelete' in request.form:
            # Ensure the user submitted the correct text to confirm account deletion
            if request.form['deleteconfirmation'] == 'DELETE':
                # Delete all stored passwords for the user
                for thisStoredPassword in StoredPassword.query.filter_by(userid=current_user.id).all():
                    db.session.delete(thisStoredPassword)
                thisUser = AppUser.query.filter_by(id=current_user.id).first()
                # delete the user
                db.session.delete(thisUser)
                db.session.commit()
                # logout the user
                logout_user()
                return render_template('base.html', title="User Logout",
                                       messsage="User Deleted and Logged out Successfully", displayLogonForm=True)
            else:
                return render_template('user-management.html', title="User Management",
                                       message="User Not Deleted, confirmation not provided", displayLogonForm=False,
                                       name=current_user.name, displayUserRegisterForm=False, user=tmpUser)
        db.session.commit()

    thisUser = AppUser.query.filter_by(id=current_user.id).first()
    tmpUser['username'] = thisUser.username
    tmpUser['email'] = thisUser.email

    return render_template('user-management.html', title="User Management", displayLogonForm=False,
                           name=current_user.name, displayUserRegisterForm=False, user=tmpUser,
                           passwordchangefail=passwordChangeFail, userchanges=userChangesApplied)


# Password Generation URL Route and Password Generation View Function
@app.route('/pwd-gen', methods=["GET", "POST"])
# Login Required to reach this URL Route
@login_required
def password_generation():
    # Initialize function variables
    genpass = ""
    passent = 0
    thislower, thisupper, thisnumber, thisspec = False, False, False, False
    passstrength = ""
    generationmessage = ""
    # if the request method was a post meaning there was user submission
    if request.method == 'POST':
        # Set all the variables based on user input
        if request.form['length']:
            if all(x.isdigit() for x in request.form['length']):
                thislength = int(request.form["length"])
            else:
                generationmessage += 'Please submit an integer value for length.  '
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
        if not all([thislower, thisupper, thisnumber, thisspec]):
            generationmessage += 'Password not generated, Character Inclusions not chosen.  '
        else:
            # build the charlist to use for password generation
            charlist = buildCharSet(thislower, thisupper, thisnumber, thisspec)
            # generate the password based ont he charlist and length
            genpass = password(thislength, charlist)
            # calculate entropy of the generated password
            passent = "%.0f" % entropyCalc(genpass)
            passstrength = passwordStrength(int(passent))

    return render_template('password-generation.html', title="Password Generation", displayLogonForm=False,
                           name=current_user.name, generated_password=genpass, message=generationmessage,
                           generated_password_entropy=passent, generated_password_strength=passstrength)


# Password Entropy Calculator URL Route and Password Entropy Calculator View Function
@app.route('/pwd-calc', methods=["GET", "POST"])
# Login Required to reach this URL Route
@login_required
def password_entropy_calculator():
    # Initialize function variables
    subpass = ""
    subpassent = 0
    passstrength = ""
    entcalcmessage = ""


    # If the request method is a post meaning the user submitted data
    if request.method == 'POST':
        if ('subpass' in request.form) and (request.form['subpass'] != ''):
            subpass = request.form["subpass"]
            # Calculate Entropy of the submitted password
            subpassent = "%.0f" % entropyCalc(request.form['subpass'])
            passstrength = passwordStrength(int(subpassent))
        else:
            entcalcmessage = 'Please specify a password to calculate.'

    return render_template('password-entropy-calculator.html', title="Password Entropy Calculator",
                           displayLogonForm=False, name=current_user.name, submitted_password=subpass,
                           submitted_password_entropy=subpassent, submitted_password_strength=passstrength,
                           message=entcalcmessage)


# Password Storage URL Route and Password Storage View Function
@app.route('/pwd-store', methods=["GET", "POST"])
# Login Required to reach this URL Route
@login_required
def password_storage():
    displayList = []
    failedSubmission = False
    storagemessage = ''
    if request.method == 'POST':
        # If the user opted to delete all passwords
        if 'deleteall' in request.form:
            # Ensure the users input was DELETE signifying they want to delete all passwords
            if request.form["deleteall"] == 'DELETE':
                # Iterate thru all stored passwords and delete each one that matches current user id
                for thisStoredPassword in StoredPassword.query.filter_by(userid=current_user.id).all():
                    db.session.delete(thisStoredPassword)
                # Commit the deletions to the database
                db.session.commit()
                storagemessage = 'Passwords deleted'
            else:
                storagemessage = 'Passwords not deleted, necessary confirmation text not provided.'
        # Check to see if the user has clicked Display to show a password
        if 'display' in request.form:
            # Add the current stored password ID to the displaylist
            displayList.append(int(request.form['passid']))
        # If the user has submitted a new stored password record
        if 'newpass' in request.form:
            # Initialize the temporary variables
            if ('username' in request.form) and (request.form['username'] != ''):
                username = request.form["username"]
            else:
                failedSubmission = True
            if ('passwd' in request.form) and (request.form['passwd'] != ''):
                # Encrypt Password before storage
                f = Fernet(key)
                tmpPass = bytes(request.form["passwd"], 'utf-8')
                encpassword = f.encrypt(tmpPass)
            else:
                failedSubmission = True
            if ('location' in request.form) and (request.form['location'] != ''):
                location = request.form["location"]
            else:
                failedSubmission = True

            if not failedSubmission:
                # Create a new StoredPassword Model Object
                newpassword = StoredPassword(username=username, password=encpassword, acctlocation=location,
                                             userid=current_user.id)
                # Add the new Stored Password Model Object to the Database Session
                db.session.add(newpassword)
                # Commit the new object to the Database.
                db.session.commit()
                storagemessage = 'Password Stored Successfully'
            else:
                storagemessage = 'Password not stored.  Please fill all required fields.'

    passwordList = []

    # Query passwords from the store passwords model based on the logged in userid
    thesePasswords = StoredPassword.query.filter_by(userid=current_user.id).all()

    # Iterate thru the queried passwords
    for thisPassword in thesePasswords:
        # If the password is in the displaylist the password while be displayed else it will be obscured.
        if thisPassword.id in displayList:
            f = Fernet(key)
            # Decrypt the password so it can be displayed to the user
            passwordToPass = f.decrypt(thisPassword.password).decode('utf-8')
        else:
            passwordToPass = "*****"

        # Append the password and required data to a list
        passwordList.append([thisPassword.acctlocation, thisPassword.username, passwordToPass, thisPassword.id])

    return render_template('password-storage.html', title="Password Storage", displayLogonForm=False,
                           name=current_user.name, passwords=passwordList, message=storagemessage)


# Password Mod URL Route and Password Mod View Function
@app.route('/pwd-mod', methods=["POST"])
# Login Required to reach this URL Route
@login_required
def password_modification():
    # Flag indicating a modification has been made
    passwordModded = False

    # If the submission to this page was sent by password-storage
    if 'mod' in request.form:
        # Query the list of passwords for the current user
        thesePasswords = StoredPassword.query.filter_by(userid=current_user.id).all()
        # Iterate thru users stored passwords
        for thisPassword in thesePasswords:
            # if the current passwords id matches that which is to be modified
            if thisPassword.id == int(request.form['passid']):
                # save a copy of the current password
                tmpPass = thisPassword
                # delete the password record
                db.session.delete(thisPassword)
                # Commit deletion to the database
                db.session.commit()
        # pass the copy of the current password to this page
        return render_template('password-modification.html', title="Password Modification", displayLogonForm=False,
                                name=current_user.name, passwordToDisplay=tmpPass)

    # if the submission has been sent from this page
    if 'modpass' in request.form:
        # Initial the stored password variables
        username = request.form["username"]
        f = Fernet(key)
        tmpPass = bytes(request.form["passwd"], 'utf-8')
        # Encrypt the password before storage
        newpass = f.encrypt(tmpPass)
        location = request.form["location"]

        # Create a new StoredPassword Model Object
        newpassword = StoredPassword(username=username, password=newpass, acctlocation=location,
                                     userid=current_user.id)
        # Add the Model Object to the DB Session
        db.session.add(newpassword)
        # Commit the Addition to the DB
        db.session.commit()
        # Set the Password Modification Flag
        passwordModded = True

    return render_template('password-modification.html', title="Password Modification", displayLogonForm=False,
                           name=current_user.name, passwordModified=passwordModded)


# Password Deletion URL Route and Password Deletion View Function
@app.route('/pwd-del', methods=["POST"])
# Login Required to reach this URL Route
@login_required
def password_deletion():
    deletionmessage = ''
    if 'delpass' in request.form:
        for thisStoredPassword in StoredPassword.query.filter_by(userid=current_user.id).all():
            # If the current password matches the record ID submitted by the user
            if thisStoredPassword.id == int(request.form['passid']):
                # Delete the password model object
                db.session.delete(thisStoredPassword)
                deletionmessage = 'Password Successfully Deleted'
        # Commit the deletion to the database
        db.session.commit()
        return render_template('password-deletion.html', title="Password Deletion", displayLogonForm=False,
                                name=current_user.name, message=deletionmessage)
    # If the user opted to delete a password
    if 'delete' in request.form:
        # Iterate thru all stored passwords
        for thisStoredPassword in StoredPassword.query.filter_by(userid=current_user.id).all():
            if thisStoredPassword.id == int(request.form['passid']):
                tmpPassword = thisStoredPassword
        return render_template('password-deletion.html', title="Password Deletion", displayLogonForm=False,
                                name=current_user.name, message=deletionmessage, passwordToDisplay=tmpPassword)

# User Logout URL Route and User Logout View Function
@app.route('/logout')
# Login Required to reach this URL Route
@login_required
def logout():
    logout_user()
    return render_template('base.html', title="User Logout", messsage="User Logged out Successfully",
                           displayLogonForm=True)


# Login Manager load_user Definition
@login_manager.user_loader
def load_user(userid):
    return User(userid)


# If application was executed and not imported, start app
if __name__ == '__main__':
    app.run(debug=True)
