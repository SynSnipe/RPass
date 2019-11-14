#!/usr/bin/env python3

# Imports
from flask import Flask, request, render_template, redirect, Response, abort, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import argparse
import sys

# Define Flask App
global app
app = Flask(__name__)
app.debug = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users//sean_local//PycharmProjects//pwd_gen_ent_calc//test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'


# Define SQLAlchemy Database Object
global db
db = SQLAlchemy(app)


# Define Flask Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


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


class User(UserMixin):

    def __init__(self, id):
        curruser = AppUser.query.filter_by(id=id)
        self.id = id
        self.name = curruser.nam
        #self.password = password

    def __repr__(self):
        return "%d/%s/%s" % (self.id)#, self.name, self.password)


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


# class User(UserMixin):
#     def __init__(self, id):
#         self.id = id
#         self.name = "user" + str(id)
#         self.password = self.name + "_secret"
#
#     def __repr__(self):
#         return "%d%s%s" % (self.id, self.name, self.password)
#
#
# users = [User(id) for id in range(1,5)]


@app.route('/')
def home_page():
    if current_user.is_authenticated:
        return render_template('base.html', title="Home", displayLogonForm=False, name=current_user.name)
    else:
        return render_template('base.html', title="Home", displayLogonForm=True)


@app.route('/user_register')
def user_register():
    if request.method == 'POST':
        pass
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        return render_template('base.html', title="User Registration", displayLogonForm=False, displayUserRegisterForm=False, name=current_user.name)

    else:
        #return abort(401)
        return render_template('base.html', title="User Registration", displayLogonForm=False, displayUserRegisterForm=True)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        qusers = AppUser.query.filter_by(username=username)
        for myuser in qusers:
            if username == myuser.username:
                if password == myuser.password:
                    tmp_user = User(myuser.id, myuser.username, myuser.password)
                    login_user(tmp_user)
                    next = request.args.get('next')
                    return redirect(url_for('home_page'))
                else:
                    return abort(401)
            else:
                return abort(401)
    elif request.method == 'GET':
        if current_user.is_authenticated:
            return render_template('base.html', title="User Login", displayLogonForm=False, name=current_user.name)
        else:
            return render_template('base.html', title="User Login", displayLogonForm=True)


@app.route('/pwd-gen')
@login_required
def password_generation():
    return render_template('base.html', title="Password Generation", displayLogonForm=False, name=current_user.name)


@app.route('/pwd-store')
@login_required
def password_storage():
    return render_template('base.html', title="Password Storage", displayLogonForm=False, name=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('base.html', title="User Logout", displayLogonForm=True)


@login_manager.user_loader
def load_user(userid):
    # For SQLAlchemy
    return User(userid)
    #return User(userid)


def main():
    parser = argparse.ArgumentParser(description='Passwd Generator w/ Entropy & Strength Calculator')
    parser.add_argument('-c', '--createdb', action="store_true", help="Create Initial Database")
    parser.add_argument('-p', '--port', help="Server Port")
    parser.add_argument('-d', '--debug', action="store_true", help="Debug Output")
    global args
    args = parser.parse_args()

    if args.createdb:
        try:
            db.create_all()
        except Exception as e:
            print(f"*** EXCEPTION ***: {e}")
        sys.exit(0)


if __name__ == '__main__':
    app.run(debug=True)
