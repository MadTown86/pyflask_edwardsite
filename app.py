# Description: This file contains the main code for the Flask Application

# Importing Libraries
import logging
import os
import flask

# Importing Specific Libraries
from os.path import join, dirname
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, \
request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import time as tt
from authlib.integrations.flask_client import OAuth

# Load Environment Variables
load_dotenv()

# Create Flask App
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# MySQL Config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Google Auth Config
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url=CONF_URL,
    client_kwargs={'scope': 'openid email profile'}
)

# MySQL User Class
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    fN = db.Column(db.String(255), nullable=False)
    lN = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

# MySQL message Class
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)

class ResetRequest(db.Model):
    __tablename__ = 'password_resets'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    reset_code = db.Column(db.String(255), nullable=False)

# Logging
handler = RotatingFileHandler("D:/DEVELOPER_FILES/REPOSITORIES/logs/pyflask_log.log", maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

year = tt.strftime("%Y")

# Basic Routes
#region Basic Routes
@app.route("/")
def index_page():
    user = session.get('user')
    return render_template("pages/index.jinja", year=year, user=user)


@app.route("/vision")
def vision_page():
    user = session.get('user')
    return render_template("/pages/vision.jinja", year=year, user=user)


@app.route("/train")
def train_page():
    user = session.get('user')
    return render_template("/pages/train.jinja", year=year, user=user)


@app.route("/reset_request")
def reset_request_page():
    user = session.get('user')
    return render_template("/pages/reset_request.jinja", year=year, user=user)

@app.route("/contact")
def contact_page():
    user = session.get('user')
    return render_template("/pages/contact.jinja", year=year, user=user)


@app.route("/register", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        email = request.form['email']
        fN = request.form['fN']
        lN = request.form['lN']
        password = request.form['password_register_verify']
        password = generate_password_hash(password)
        user = User(email=email, fN=fN, lN=lN, password=password)
        try:
            db.session.add(user)
            db.session.commit()
            flash('User Registered Successfully', 'success')
            return redirect(url_for('register_page'))
        except:
            db.session.rollback()
            flash('User Already Exists', 'danger')
            return redirect(url_for('register_page'))
    else:
        return render_template('/pages/register.jinja', year=year)


@app.route("/privacy_policy")
def privacy_policy_page():
    return render_template("/pages/privacy_policy.jinja", year=year)


@app.route("/login", methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user'] = user.email
            flash('User Login successful', 'success')
            return redirect(url_for('login_page'))
        else:
            flash('User Login Failed', 'danger')
            return redirect(url_for('login_page'))
    else:
        return render_template("/pages/login.jinja", year=year)

@app.route("/food")
def food_page():
    return render_template("/pages/food.jinja", year=year)
#endregion

@app.route("/member", methods=['GET', 'POST'])
def member_page():
    user = session.get('user')
    if request.method == 'GET':
        user = session.get('user')
        if user:
            return render_template("/pages/member.jinja", year=year, user=user)
        else:
            return redirect(url_for('login_page'))
    elif request.method == 'POST':
        #TODO Write code for post method on member page, perhaps allow password change right there.
        return redirect(url_for('member_page'))
        

#region Google Auth Routes
@app.route("/auth/google")
def auth_google():
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    token = oauth.google.authorize_access_token()
    session['user'] = token['userinfo']
    print(session['user'].email)
    return redirect(url_for('index_page'))
#endregion

# Logout Route
@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('index_page'))

# Run App
if __name__ == "__main__":
    app.run(debug=True)