import logging
import os
from os.path import join, dirname
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, \
request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
import time as tt

# Load Environment Variables
load_dotenv()

# Create Flask App
app = Flask(__name__)

# OAuth Config
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
    client_kwargs={'scope': 'openid profile email', 'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'},
)

# MySQL Config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
handler = RotatingFileHandler("C:\REPOSITORIES\\PYTHON\\pyflask_edwardsite\\flask_log", maxBytes=10000, backupCount=1)
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

@app.route("/auth/google")
def auth_google():
    redirect_uri = url_for('auth_google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(email=user_info['email'], fN=user_info['given_name'], lN=user_info['family_name'], password='google')
        db.session.add(user)
        db.session.commit()
    session['user'] = user.email
    return redirect(url_for('login_page'))

@app.route("/food")
def food_page():
    return render_template("/pages/food.jinja", year=year)

#endregion

# Run App
if __name__ == "__main__":
    app.run(debug=True)