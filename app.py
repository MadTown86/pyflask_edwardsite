# Description: This file contains the main code for the Flask Application

# Importing Libraries
import logging
import os
import flask
import json as JSON
import datetime

# Importing Specific Libraries
from os.path import join, dirname
from dotenv import load_dotenv
from logging.config import dictConfig
from logging.handlers import RotatingFileHandler
from logging.handlers import QueueHandler, QueueListener
from flask.logging import default_handler
from flask import has_request_context, request
from flask import Flask, render_template, \
redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
import time as tt
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
from logging.handlers import SMTPHandler
from collections import defaultdict
from queue import Queue


# Load Environment Variables
load_dotenv("vars\\.env")

#region Configuration
# Config Logging

logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# dictConfig({
#     'version': 1,
#     'formatters': {'default': {
#         'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
#     }},
#     'handlers': {'wsgi': {
#         'class': 'logging.StreamHandler',
#         'stream': 'ext://flask.logging.wsgi_errors_stream',
#         'formatter': 'default'
#     }},
#     'root': {
#         'level': 'DEBUG',
#         'handlers': ['wsgi']
#     }
# })

class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.url = request.url
            record.remote_addr = request.remote_addr
        else:
            record.url = None
            record.remote_addr = None

        return super().format(record)

formatter = RequestFormatter(
    '[%(asctime)s] %(remote_addr)s requested %(url)s\n'
    '%(levelname)s in %(module)s: %(message)s'
)

# Logging Queue
# log_queue = Queue()
# queue_handler = QueueHandler(log_queue)

# Logging Handlers
# debug_handler = RotatingFileHandler(os.getenv("FILE_HANDLER_LOCATION"), maxBytes=10000, backupCount=1)
# debug_handler.setLevel(logging.DEBUG)
# debug_handler.setFormatter(formatter)
# listener = QueueListener(log_queue, debug_handler)

# request_db_handler = RotatingFileHandler(os.getenv("REQUEST_HANDLER_LOCATION"), maxBytes=10000, backupCount=1)
# request_db_handler.setLevel(logging.INFO)
# request_db_handler.setFormatter(formatter)
# listener_db = QueueListener(log_queue, request_db_handler)

# Create Flask App
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Add Handler to App Logger
# app.logger.addHandler(debug_handler)
# app.logger.addHandler(request_db_handler)
# app.logger.addHandler(queue_handler)
# app.logger.info("Application Started")
# listener.start()
# listener_db.start()

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

# MySQL Config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 28800
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
# Facebook Auth Config
oauth.register(
    name='facebook',
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email public_profile'},  
)

# Pre-defined Module Level Variables
now = datetime.now
year = tt.strftime("%Y")

#endregion Configuration-

#region MySQL Classes
# MySQL User Class
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    fN = db.Column(db.String(255), nullable=False)
    lN = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(255), nullable=False, default='native')
    token = db.Column(db.String(255), nullable=True, default=None)

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
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    expires_at = db.Column(db.DateTime, default=(datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"))

# MySQL Schedule Class
class Trainers(db.Model):
    __tablename__ = 'trainers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(255), nullable=False)

# MySQL Services Class
class Services(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)

# MySQL Appointments Class
class Appointments(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainers.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    appointment_date = db.Column(db.Date, nullable=False)
    appointment_time = db.Column(db.Time, nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    db.UniqueConstraint('trainer_id', 'appointment_date', 'appointment_time', name='unique_appointment')
    
# with app.app_context():
#     db.create_all()
#     service = Services(name='Consultation', description='Consultation with a trainer', price=0.00)
#     db.session.add(service)
#     trainer = Trainers(name='Edward', email='unicornslayerbih@gmail.com', phone='2242874378')
#     db.session.add(trainer)
#     try:
#         db.session.commit()
#     except Exception as e:
#         db.session.rollback()
#         print(e)

#endregion MySQL Classes

#region Logging Decorators
@app.before_request
def log_and_prepare_request():
    app.logger.debug('\n\nRequest: %s %s', request.method, request.url)
    db.session.query(text('SET SESSION sql_mode="TRADITIONAL"')) 
    
@app.after_request
def log_response_info(response):
    app.logger.debug('\n\nResponse: %s', response.status)
    return response

@app.teardown_request
def log_request_time(exception=None):
    app.logger.debug('\n\nRequest Time: %s', tt.time())
    
    
#endregion Logging Decorators

#region Error Handling
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error('\n\nAn error occurred during a request.', exc_info=e)
    return 'An internal error occurred', 500

#endregion Error Handling



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

# Route to Display Privacy Policy
@app.route("/privacy_policy")
def privacy_policy_page():
    return render_template("/pages/privacy_policy.jinja", year=year)

# Route to Render Food Page
@app.route("/food")
def food_page():
    user = session.get('user')
    return render_template("/pages/food.jinja", year=year, user=user)

# Route for User Contact
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


# Route To Member Page
@app.route("/member", methods=['GET'])
def member_page():
    user = session.get('user')
    if request.method == 'GET':
        user = session.get('user')
        if user:
            try: 
                appointments = Appointments.query.filter_by(customer_id=user['id']).all()
                if appointments:
                    print(appointments[0].appointment_date, appointments[0].appointment_time, appointments[0].confirmed)
                    return render_template("/pages/member.jinja", year=year, user=user, appointments=appointments, current_date=datetime.now())
                else:
                    flash('No Appointments Found', 'danger')
                    return render_template("/pages/member.jinja", year=year, user=user)
            except Exception as e:
                print(e)
                flash('Error Fetching Appointments', 'danger')
                return redirect(url_for('member_page'))
        else:
            return redirect(url_for('login_page'))
        
#endregion Basic Routes

#region Route User Registration/Login/Reset/Delete
# Route To Reset Request Page
@app.route("/reset_request", methods=['GET', 'POST'])
def reset_request_page():
    user = session.get('user')
    if user and user.type != 'google':
        return render_template("/pages/reset_request.jinja", year=year, user=user)
    elif not user:
        if request.method == 'GET':
            return render_template("/pages/reset_request.jinja", year=year, user=user)
        elif request.method == 'POST':
            try:
                user_email = request.form['email_reset_password']
                users = User.query.filter_by(email=user_email).all()
                if not users:
                    flash('User Not Found', 'danger')
                    return redirect(url_for('reset_request_page'))
                else:
                    user_types = []
                    for user in users:
                        if user.user_type == 'native':
                            reset_code = os.urandom(16).hex()
                            try:
                                msg = Message(subject="Reset Request - Visions.Fit", \
                                            body=f'Dear User:\nPlease click the link below to reset your password:\n', html=f'<html><p>Dear User:</p><p>Please click the link below to reset your password:</p><p><a href="www.visions.fit/email_reset/{reset_code}">click here</a></p></html>', \
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
                        else:
                            user_types.append(user.user_type)
                            continue
                    flash(f'User Types Cannot Be Reset: {user_types}', 'danger')
                    return redirect(url_for('reset_request_page'))
            except Exception as e:
                print(e)
                flash('Reset Email Failed', 'danger')
                return redirect(url_for('reset_request_page'))
                
# Route To Reset Page From Email
@app.route("/email_reset/<reset_code>", methods=['GET'])
def email_reset_page(reset_code):
    reset_code = reset_code
    print(reset_code)
    user = session.get('user')
    if request.method == 'GET':
        try:
            user_reference = ResetRequest.query.filter_by(reset_token=reset_code).first()
            print(user_reference.user_id, user_reference.expires_at, user_reference.created_at)
            if user_reference.expires_at < datetime.utcnow():
                flash('Reset Request Expired', 'danger')
                return redirect(url_for('reset_request_page'))
            else:
                user = User.query.filter_by(id=user_reference.user_id).first()
                session['user'] = {'email':user.email, 'id':user.id}
                return render_template("/pages/reset.jinja", year=year, user=user)
        except Exception as e:
            print(e)
            flash('Reset Request Not Found', 'danger')  
            return redirect(url_for('reset_request_page'))

# Route To Reset Page                     
@app.route("/reset", methods=['GET', 'POST'])
def reset_page():
    user = session.get('user')
    print(user)
    if not user:
        print("No User")
        return redirect(url_for('login_page'))
    else:
        print("User Found")
        if request.method == 'GET':
            user_match = User.query.filter_by(id=user['id']).first()
            if user_match.user_type != 'native':
                flash('Non Native Users Cannot Reset Password - Please Try Google/Twitter/Facebook Logins', 'danger')
                return redirect(url_for('login_page'))
            return render_template("/pages/reset.jinja", year=year, user=user)
        elif request.method == 'POST':
            if not user:
                flash('User Not Found', 'danger')
                return redirect(url_for('login_page'))
            else:
                try:
                    user = User.query.filter_by(id=user['id']).first()
                except Exception as e:
                    print("Exception Querying User:", e)
                    flash('User Not Found', 'danger')
                    return redirect(url_for('login_page'))
                try:
                    password = request.form['password_reset_verify']
                    user.password = generate_password_hash(password)
                    db.session.add(user)
                    db.session.commit()
                    flash('Password Reset Successful', 'success')
                    return redirect(url_for('login_page'))
                except Exception as e:
                    print("Database Exception When Resetting Password", e.orig, e.params)
                    db.session.rollback()
                    flash('Password Reset Failed - Contact Site Administrator', 'danger')
                    return redirect(url_for('reset_page'))
        
# Route to Rigister Page
@app.route("/register", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        email = request.form['email']
        fN = request.form['fN']
        lN = request.form['lN']
        password = request.form['password_register_verify']
        password = generate_password_hash(password)
        user = User(email=email, fN=fN, lN=lN, password=password, user_type='native')
        # Check If User Exists Already
        # Check Both Types of Google Email Domains
        try:
            if email.split('@')[1] == 'googlemail.com':
                email_alternate = email.split('@')[0] + '@gmail.com'
                user_exists = User.query.filter_by(email=email).all()
                if not user_exists:
                    user_exists = User.query.filter_by(email=email_alternate).all()
            elif email.split('@')[1] == 'gmail.com':
                email_alternate = email.split('@')[0] + '@googlemail.com'
                user_exists = User.query.filter_by(email=email).all()
                if not user_exists:
                    user_exists = User.query.filter_by(email=email_alternate).all()
            if user_exists:
                flash(f'User Already Exists - Login Credentials "{user_exists[0].user_type}"', 'danger')
                return redirect(url_for('register_page'))
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

# Route To Login Page
@app.route("/login", methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            users = User.query.filter_by(email=email).all()
        except Exception as e:
            print(e)
            flash('Error Fetching User', 'danger')
            return redirect(url_for('login_page'))
        if not users:
            flash("User Not Found or Database Error", 'danger')
            return redirect(url_for('login_page'))
        else:
            user_types = []
            for user in users:
                print(user.id, user.email, user.user_type)
                if user.user_type == 'native':
                    if user and check_password_hash(user.password, password):
                        session['user'] = {"email":user.email, "id":user.id, "user_type":user.user_type}
                        return render_template('pages/member.jinja', year=year, user=user)
                else:
                    user_types.append(user.user_type)
                    continue
            print("Failed Here")
            flash(f'Incorrect Login Credentials', 'danger')
            return redirect(url_for('login_page'))
    if request.method == 'GET':
        user = session.get('user')
        if user:
            return render_template('/pages/member.jinja', year=year, user=user)
        else:
            return render_template('/pages/login.jinja', year=year, user=user)
        
# Route To Delete Page
@app.route("/delete", methods=['GET', 'POST'])
def delete_page():
    user = session.get('user')
    if request.method == 'GET':
        if user:
            return render_template("/pages/delete.jinja", year=year, user=user)
        else:
            return redirect(url_for('login_page'))
    elif request.method == 'POST':
        if user:
            confirmation = request.form['delete_confirmation']
            if confirmation != 'DELETE':
                flash('Confirmation Failed', 'danger')
                return redirect(url_for('delete_page'))
            else:
                try:
                    user = User.query.filter_by(id=user['id']).first()
                    user_appointments = Appointments.query.filter_by(customer_id=user.id).all()
                    for appointment in user_appointments:
                        db.session.delete(appointment)
                    db.session.delete(user)
                    db.session.commit()
                    session.pop('user', None)
                    flash('User Deleted Successfully', 'success')
                    return redirect(url_for('login_page'))
                except Exception as e:
                    print(e)
                    db.session.rollback()
                    flash('Error Deleting User', 'danger')
                    return redirect(url_for('delete_page'))
        else:
            flash('User Not Found', 'danger')
            return redirect(url_for('login_page'))
#endregion

# Route To Schedule Page
@app.route("/schedule", methods=['GET', 'POST'])
def schedule_page():
    #TODO Need to gray out same-day appointments that are already past the current time
    #TODO Need to figure out why confirmation of appointment does not show up in member page right after scheduling
    #TODO Need to add a limit to amount of appointments one can schedule at a time
    #TODO Need to add secondary list for confirmed appointments and for past appointments
    date = datetime.now().strftime("%m/%d/%Y")
    datefmtinput = '%m/%d/%Y %H:%M:%S'
    datefmtoutput = '%I:%M %p'
    datefmtreq = '%m/%d/%Y %I:%M %p'
    justdate = '%m/%d/%Y'
    timeslots = ['09:00:00', '10:00:00', '11:00:00', '12:00:00', '13:00:00', '14:00:00', '15:00:00', '16:00:00', '17:00:00']
    for i in range(len(timeslots)):
        timeslots[i] = datetime.strptime(date + ' ' + timeslots[i], datefmtinput).strftime(datefmtoutput)
    user = session.get('user')
    if request.method == 'GET':
        try:
            # Fetch Appointments
            #TODO Filter By Trainer and Pull Less Information
            appointments = Appointments.query.group_by(Appointments.appointment_date).all()
            db.session.close()
            
            # Group Appointments By Date in DefaultDict
            appts_by_date = defaultdict(list)
            for appt in appointments:
                appts_by_date[appt.appointment_date.strftime(justdate)].append(appt.appointment_time.strftime(datefmtoutput))
            
            # Convert DefaultDict to Python Dictionary for JSON serialization/mapping
            appts_to_pydict = {}
            busy_today = []
            for key, values in appts_by_date.items():
                appts_to_pydict[key] = values
            for key, values in appts_by_date.items():
                if key == date:
                    busy_today = values
            print(busy_today)
            to_json = JSON.dumps(appts_to_pydict)

            # Get Appointment Dates Alone No Values
            appointment_dates = list(appts_by_date.keys())
            return render_template("/pages/schedule.jinja", year=year, user=user, timeslots=timeslots, date=date, appointment_dates=appointment_dates, appts_by_date=appts_by_date, json_appts=to_json, busy_today=busy_today)
        except Exception as e:
            print(e)
            flash('Error Fetching Appointments', 'danger')
            return redirect(url_for('member_page'))
        
    elif request.method == 'POST':
        data = request.get_json()
        date_post = data['date']
        time = data['time']
        appt_request = datetime.strptime(date_post + ' ' + time, datefmtreq)
        print(appt_request)
        try:
            appt = Appointments(trainer_id=1, service_id=1, customer_id=user['id'], appointment_date=appt_request, appointment_time=appt_request.time())
            db.session.add(appt)
            db.session.commit()
            flash('Appointment Request Sent', 'success')
            return redirect(url_for('member_page'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('Error Scheduling Appointment', 'danger')
            return redirect(url_for('member_page'))
        
# Route to appointments page
@app.route("/appointments", methods=['GET', 'POST'])
def appointments_page():
    user = session.get('user')
    if request.method == 'GET':
        if user:
            try:
                appointments = Appointments.query.filter_by(customer_id=user['id']).all()
                for appointment in appointments:
                    if appointment.appointment_date < datetime.now():
                        db.session.delete(appointment)
                        db.session.commit()
                    elif appointment.appointment_date == datetime.now() and datetime.date(appointment.appointment_time) < datetime.now():
                        db.session.delete(appointment)
                        db.session.commit()
                    else:
                        return render_template("/pages/appointments.jinja", year=year, user=user, appointments=appointments)
            except Exception as e:
                print(e)
                flash('Error Fetching Appointments', 'danger')
                return redirect(url_for('member_page'))
        else:
            return redirect(url_for('login_page'))
    elif request.method == 'POST':
        appointment_id = request.form['appointment_id']
        return redirect(url_for('member_page'))
    
        
#region Google Auth Routes
@app.route("/auth/google")
def auth_google():
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/facebook")
def auth_facebook():
    redirect_uri_facebook = url_for('auth_facebook_callback', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri_facebook)

@app.route("/auth/facebook/callback")
def auth_facebook_callback():
        token = oauth.facebook.authorize_access_token()
        resp = oauth.facebook.get(
            'https://graph.facebook.com/me?fields=id,name,email')
        profile = resp.json()
        print("Facebook User ", profile)
        email = profile['email']
        user_lookup = User.query.filter_by(email=email).all()
        if not user_lookup:
            user_fN, user_lN = profile['name'].split(' ')
            user = User(email=email, fN=user_fN, lN=user_lN, password='facebook', user_type='facebook')
            db.session.add(user)
            db.session.commit()
            session['user'] = {"email":email, "id":user.id, "user_type":user.user_type}
            flash('User Registered Successfully', 'success')
            return redirect(url_for('member_page'))
        else:
            user_type = user_lookup[0].user_type
            if user_type == 'facebook':
                session['user'] = {'id':user_lookup[0].id, 'email':user_lookup[0].email, 'user_type':user_lookup[0].user_type}
                user = session.get('user')
                flash('User Logged In Successfully', 'success')
                return redirect(url_for('member_page'))
            else:
                login_type = 'facebook'
                return render_template("/pages/warning.jinja", year=year, account_type=user_lookup[0].user_type, login_type='facebook', email=email)
        
    

# Google Auth Callback Route
@app.route("/auth/google/callback")
def auth_google_callback():
    """
    Retrieve access token
    Check for users with both types of email domain

    """
    token = oauth.google.authorize_access_token()
    user_info_google = token['userinfo']
    email = user_info_google['email']
    if email.split('@')[1] == 'googlemail.com':
        email_alternate = email.split('@')[0] + '@gmail.com'
    user_lookup = User.query.filter_by(email=email).all()
    if not user_lookup:
        user_lookup = User.query.filter_by(email=email_alternate).all()
    print('\n\n***THIS IS USER LOOKUP*** \n\n', user_lookup)
    if not user_lookup:
        user_fN = user_info_google['given_name']
        user_lN = user_info_google['family_name']
        user = User(email=email, fN=user_fN, lN=user_lN, password='google', user_type='google')
        db.session.add(user)
        db.session.commit()
        session['user'] = {"email":email, "id":user.id, "user_type":user.user_type}
        flash('User Registered Successfully', 'success')
        return redirect(url_for('member_page'))
    else:
        if user_lookup[0].user_type == 'google':
            session['user'] = {'id':user_lookup[0].id, 'email':user_lookup[0].email, 'user_type':user_lookup[0].user_type}
            user = session.get('user')
            flash('User Logged In Successfully', 'success')
            return redirect(url_for('member_page'))
        else:
            return render_template("/pages/warning.jinja", year=year, account_type=user_lookup[0].user_type, login_type='google', email=user_lookup[0].email)
        
@app.route("/rewrite_credentials", methods=['POST'])
def rewrite_credentials():
    if request.method == 'POST':
        #TODO get user information and write credentials to database to over-write login credentials with an alternate approved credential
        change_to = request.form.get("login_type")
        login_type = request.form.get("account_type")
        email = request.form.get("email")
        user = User.query.filter_by(email=email).all()
        if not user:
            flash("Email Not Found", "danger")
            return redirect(url_for('login_page'))
        else:
            if change_to == 'google' or change_to == 'facebook':
                user = user[0]
                password = change_to
                user.user_type = change_to
                user.password = password
                db.session.add(user)
                db.session.commit()
                session['user'] = {'id':user.id, 'email':user.email, 'user_type':user.user_type}
                flash('User Logged In Successfully and Login Type Changed', 'success')
                return redirect(url_for('member_page'))
            else:
                flash('<p>You Cannot Change To Native Login From OAuth,</p> <p>Please Delete Account and Re-Register</p>', 'danger')
    
#endregion

# Logout Route
@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('index_page'))

#region Testing Routes
@app.route("/test", methods=['GET', 'POST'])
def test_page():
    current_time = datetime.now()
    user = session.get('user')
    if request.method == 'GET':
        user = session.get('user')
        try: 
            appointments = Appointments.query.filter_by(customer_id=user['id']).all()
            print(appointments[0].appointment_date, appointments[0].appointment_time, appointments[0].confirmed)
        except Exception as e:
            print(e)
            flash('Error Fetching Appointments', 'danger')
            return redirect(url_for('test_page'))
        
        if user:
            return render_template("/pages/test.jinja", year=year, user=user, appointments=appointments, current_time=current_time)
        else:
            return redirect(url_for('login_page'))
        
    elif request.method == 'POST':
        #TODO Write code for post method on member page, perhaps allow password change right there.
        return redirect(url_for('member_page'))


#endregion Testing Routes

# Run App
if __name__ == "__main__":
    app.run(debug=True)
    app.logger.info("Application Started")