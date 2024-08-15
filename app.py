import logging
import os
from os.path import join, dirname
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, \
request, redirect, url_for, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import time as tt

# Load Environment Variables
load_dotenv()

# Create Flask App
app = Flask(__name__)

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
    return render_template("/pages/register.jinja", year=year)


@app.route("/privacy_policy")
def privacy_policy_page():
    return render_template("/pages/privacy_policy.jinja", year=year)


@app.route("/login")
def login_page():
    return render_template("/pages/login.jinja", year=year)


@app.route("/food")
def food_page():
    return render_template("/pages/food.jinja", year=year)

#endregion

# Run App
if __name__ == "__main__":
    app.run(debug=True)