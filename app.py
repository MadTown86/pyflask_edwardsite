# Description: This file contains the main code for the Flask Application

# Importing Libraries
import logging
import os
import flask

# Importing Google Libraries
import google_auth_oauthlib.flow


# Importing Specific Libraries
from os.path import join, dirname
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, \
request, redirect, url_for, session, flash
from flask_oauthlib.client import OAuth
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import time as tt

# Load Environment Variables
load_dotenv()

# Create Flask App
app = Flask(__name__)

# MySQL Config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Google Auth Config
oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=os.getenv("GOOGLE_CLIENT_ID"),
    consumer_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth'
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
    return render_template("pages/index.jinja", year=year)


@app.route("/vision")
def vision_page():
    return render_template("/pages/vision.jinja", year=year)


@app.route("/train")
def train_page():
    return render_template("/pages/train.jinja", year=year)


@app.route("/reset_request")
def reset_request_page():
    return render_template("/pages/reset_request.jinja", year=year)

@app.route("/contact")
def contact_page():
    return render_template("/pages/contact.jinja", year=year)


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

#region Google Auth Routes
@app.route("/auth/google")
def auth_google():
    #Task: Implement Google Auth
    return google.authorize(callback=url_for('auth_google_callback', _external=True))

@app.route("/auth/google/callback")
def auth_google_callback():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(request.args['error_reason'], request.args['error_description'])
    session['google_token'] = (response['access_token'], '')
    return redirect(url_for('index_page'))
#endregion

# Run App
if __name__ == "__main__":
    app.run(debug=True)