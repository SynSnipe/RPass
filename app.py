#!/usr/bin/env python3

# Imports
from flask import Flask, request, render_template, redirect, Response, abort, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy


# Define Flask App
global app
app = Flask(__name__)
app.debug = False
# This line is for Sean's development system, you may need to use the line commented below it
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users//sean_local//PycharmProjects//pwd_gen_ent_calc//test.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'


# Define SQLAlchemy Database Object
global db
db = SQLAlchemy(app)


# Define Flask Login
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
# CURRENTLY NOT USED AND NEEDS MORE DEVELOPMENT
class StoredPassword(db.Model):
    id = db.Column(db.Integer,
                   primary_key=True)

    acctlocation = db.Column(db.String(120),
                             unique=True,
                             nullable=False)

    password = db.Column(db.String(120),
                         unique=True,
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
        for myuser in qusers:
            if username == myuser.username:
                if password == myuser.password:
                    tmp_user = User(myuser.id)
                    login_user(tmp_user)
                    next = request.args.get('next')
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
@app.route('/pwd-gen')
@login_required
def password_generation():
    return render_template('base.html', title="Password Generation", displayLogonForm=False, name=current_user.name)


# Password Storage URL Route and Password Storage View Function
@app.route('/pwd-store')
@login_required
def password_storage():
    return render_template('base.html', title="Password Storage", displayLogonForm=False, name=current_user.name)


# User Logout URL Route and User Logout View Function
@app.route('/logout')
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
