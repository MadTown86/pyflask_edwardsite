from flask import Flask, render_template
import time as tt

app = Flask(__name__)

year = tt.strftime("%Y")

# Basic Routes
#region Basic Routes
@app.route("/")
def index_page(year=year):
    return render_template("/pages/index.jinja", year=year)

@app.route("/vision")
def vision_page(year=year):
    return render_template("/pages/vision.jinja", year=year)

@app.route("/train")
def train_page(year=year):
    return render_template("/pages/train.jinja", year=year)

@app.route("/reset_request")
def reset_request_page(year=year):
    return render_template("/pages/reset_request.jinja", year=year)

@app.route("/contact")
def contact_page(year=year):
    return render_template("/pages/contact.jinja", year=year)

@app.route("/register")
def register_page(year=year):
    return render_template("/pages/register.jinja", year=year)

@app.route("/privacy_policy")
def privacy_policy_page(year=year):
    return render_template("/pages/privacy_policy.jinja", year=year)

@app.route("/login")
def login_page(year=year):
    return render_template("/pages/login.jinja", year=year)

@app.route("/food")
def food_page(year=year):
    return render_template("/pages/food.jinja", year=year)
#endregion




# if __name__ == "__main__":
#     print(year)
#     app.run(
#         host='localhost',
#         port=5000,
#         debug=True
#     )