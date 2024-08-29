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
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from logging.handlers import SMTPHandler

# Load Environment Variables
load_dotenv("vars\\.env")

# Create Flask App
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# MySQL Config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask_Mail Config
print(os.getenv("MAIL_SERVER"), os.getenv("MAIL_PORT"), os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False
app.config['MAIL_DEBUG'] = True
mail = Mail(app)


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
    user_type = db.Column(db.String(50), nullable=False)

# MySQL message Class
class MessageDB(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)

# MySQL Reset Request Class
class ResetRequest(db.Model):
    __tablename__ = 'password_resets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reset_token = db.Column(db.String(255), nullable=False)
    # created_at = db.Column(db.DateTime, default=tt.strftime("%Y-%m-%d %H:%M:%S"))
    # expires_at = db.Column(db.DateTime, default=tt.strftime("%Y-%m-%d %H:%M:%S"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    expires_at = db.Column(db.DateTime, default=(datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"))


# Logging
handler = RotatingFileHandler(os.getenv("FILE_HANDLER_LOCATION"), maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

if not app.debug:
    mail_handler = SMTPHandler(
        mailhost=('mail.visions.fit', 465),
        fromaddr='reset@visions.fit',
        toaddrs=['grover.donlon@gmail.com'],
        subject='Application Error',
        credentials=('reset@visions.fit', 'ThePassword1-1'),
        secure=()
    )
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)

year = tt.strftime("%Y")

# Basic Routes
#region Basic Routes
@app.route("/")
def index_page():
    user = session.get('user')
    return render_template("pages/index.jinja", year=year, user=user)

# Route To Vision Page
@app.route("/vision")
def vision_page():
    user = session.get('user')
    return render_template("/pages/vision.jinja", year=year, user=user)

# Route To Train Page
@app.route("/train")
def train_page():
    user = session.get('user')
    return render_template("/pages/train.jinja", year=year, user=user)

# Route To Reset Request Page
@app.route("/reset_request", methods=['GET', 'POST'])
def reset_request_page():
    user = session.get('user')
    if user and user.type != 'google':
        return render_template("/pages/reset_request.jinja", year=year, user=user)
    else:
        if request.method == 'GET':
            return render_template("/pages/reset_request.jinja", year=year, user=user)
        elif request.method == 'POST':
            try:
                user_email = request.form['email_reset_password']
                user = User.query.filter_by(email=user_email).first()
                if not user:
                    flash('User Not Found', 'danger')
                    return redirect(url_for('reset_request_page'))
                else:
                    reset_code = os.urandom(16).hex()
                    try:
                        msg = Message(subject="Reset Request - Visions.Fit", \
                                      body=f'Dear User:\nPlease click the link below to reset your password:\n', \
                                        html=f'<html><p>Dear User:</p><p>Please click the link below to reset your password:</p><p><a href="www.visions.fit/email_reset/{reset_code}">click here</a></p></html>', \
                                        recipients=[user_email])
                        print(msg)
                        reset_request = ResetRequest(user_id=user.id, reset_token=reset_code)
                        db.session.add(reset_request)
                        db.session.commit()
                        print("sending mail")
                        with mail.connect() as conn:
                            conn.send(msg)
                        print("mail sent")
                        flash('Reset Email Sent', 'success')
                        return redirect(url_for('reset_request_page'))
                    except Exception as e:
                        print(e)
                        db.session.rollback()
                        flash('Reset Email Failed - Error In Sending Mail', 'danger')
                    return redirect(url_for('reset_request_page'))
            except Exception as e:
                print(e)
                flash('Reset Email Failed', 'danger')
                return redirect(url_for('reset_request_page'))
                
# Route To Reset Page From Email
@app.route("/email_reset/<reset_code>", methods=['GET'])
def email_reset_page(reset_code):
    reset_code = reset_code
    user = session.get('user')
    if request.method == 'GET':
        user_reference = ResetRequest.query.filter_by(reset_token=reset_code).first()
        print(user_reference.user_id, user_reference.expires_at, user_reference.created_at)
        if not user_reference:
            flash('Reset Request Not Found', 'danger')
            return redirect(url_for('reset_request_page'))
        elif user_reference.expires_at < datetime.utcnow():
            flash('Reset Request Expired', 'danger')
            return redirect(url_for('reset_request_page'))
        else:
            user = User.query.filter_by(id=user_reference.user_id).first()
            print()
            return render_template("/pages/reset.jinja", year=year, user=user)
                              
@app.route("/reset", methods=['GET', 'PATCH'])
def reset_page():
    user = session.get('user')
    if not user:
        return redirect(url_for('login_page'))
    else:
        if request.method == 'GET':
            print(user)
            return render_template("/pages/reset.jinja", year=year, user=user)
        elif request.method == 'PATCH':
            password = request.form['password']
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Password Reset Successful', 'success')
            return redirect(url_for('login_page'))


@app.route("/contact", methods=['GET', 'POST'])
def contact_page():
    user = session.get('user')
    if request.method == 'GET':
        return render_template("/pages/contact.jinja", year=year, user=user)
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        msg_tovisions = Message(
            subject='User Message - Visions.fit',
            recipients=['grover.donlon@gmail.com'],
            html=f'<html><p>Dear Visions Member!</p>{name} with email {email} has sent you the following message:</p><p>{message}</p></html>'
        )
        msg_tosender = Message(
            subject='Contact Request Message - Visions.Fit',
            html=f'<html><p>Thank you {name} for contacting Visions.Fit, Please be patient as it can take up to 48 hours for a response.</p></html>',
            recipients=[f'{email}']
        )
        try:
            with mail.connect() as conn:
                conn.send(msg_tovisions)
                conn.send(msg_tosender)
            flash('Email Sent Successfully - Please Wait 24 Hours For Your Response', 'success')
            return redirect(url_for('contact_page'))
        except Exception as e:
            print(e)
            flash('Internal Error - Please Try Again Later', 'danger')
            return redirect(url_for('contact_page'))



@app.route("/register", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        email = request.form['email']
        fN = request.form['fN']
        lN = request.form['lN']
        password = request.form['password_register_verify']
        password = generate_password_hash(password)
        user = User(email=email, fN=fN, lN=lN, password=password, user_type='native')
        try:
            db.session.add(user)
            db.session.commit()
            flash('User Registered Successfully', 'success')
            return redirect(url_for('login_page'))
        except Exception as e:
            print(e)
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
        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            print(e)
            flash('Error Fetching User', 'danger')
            return redirect(url_for('login_page'))
        if not user:
            flash("User Not Found or Database Error", 'danger')
            return redirect(url_for('login_page'))
        if user and check_password_hash(user.password, password):
            session['user'] = user.email, user.user_type
            return render_template('pages/member.jinja', year=year, user=user, user_type=user.user_type)
        else:
            print("Failed Here")
            flash('User Login Failed', 'danger')
            return redirect(url_for('login_page'))
    if request.method == 'GET':
        user = session.get('user')
        if user:
            return render_template('/pages/member.jinja', year=year, user=user)
        else:
            return render_template('/pages/login.jinja', year=year, user=user)


@app.route("/food")
def food_page():
    user = session.get('user')
    return render_template("/pages/food.jinja", year=year, user=user)
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
    email = session['user'].email
    user_fN = session['user'].given_name
    user_lN = session['user'].family_name
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, fN=user_fN, lN=user_lN, password='google', user_type='google')
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('member_page'))
    else:
        return redirect(url_for('member_page'))
#endregion

# Logout Route
@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('index_page'))

# Run App
if __name__ == "__main__":
    app.run(debug=True)