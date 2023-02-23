from flask import Flask, request, render_template, redirect, jsonify
import requests
import hashlib
import json
import datetime
import os
from dotenv import load_dotenv
from encrypt import encrypt
from decrypt import decrypt
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
password = ""
app = Flask(__name__)
auth = HTTPBasicAuth()
load_dotenv()

#users = { "admin" : generate_password_hash(password) }

def load_lures():
    try:
        with open("lures.json", "r") as f:
            return json.load(f)
    except:
        return []


lures = load_lures()


def save_lures(lures):
    with open("lures.json", "w") as f:
        json.dump(lures, f, indent=4)

def get_decrypt_password(username):
    for user, password in users.items():
        if user == username:
            return password
    return None


def get_country(ip):
    # get the api key from https://ipgeolocation.io/ and put it into a .env file
    API_KEY = os.getenv("API_KEY")
    print(API_KEY)
    response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}")
    data = response.json()
    try:
        country = data["country_name"]
    except:
        country = data["message"]
    return country


def create_lure(redirect_url):
    unique_key = hashlib.sha256(
        str(datetime.datetime.now().microsecond).encode()
    ).hexdigest()[:6]
    lure = {"id": unique_key, "redirect_url": redirect_url}
    lures.append(lure)
    save_lures(lures)
    return unique_key


def get_logs():
    try:
        with open("log.json", "r") as f:
            logs = json.load(f)
        return logs
    except:
        return []


def save_log(log):
    logs = get_logs()
    logs.append(log)
    with open("log.json", "w") as f:
        json.dump(logs, f, indent=4)


@app.route("/add-lure", methods=["GET", "POST"])
def add_lure():
    if request.method == "POST":
        redirect_url = request.form.get("redirect_url")
        if not redirect_url:
            return "Redirect URL is required", 400
        if not redirect_url.startswith("http://") and not redirect_url.startswith(
            "https://"
        ):
            redirect_url = "https://" + redirect_url
        key = create_lure(redirect_url)
        return render_template("add_lure.html", lure=key)
    return render_template("add_lure.html")


@app.route("/<key>")
@app.route("/lure/<key>")
def lure(key):
    lure = next((l for l in lures if l["id"] == key), None)
    if lure is None:
        return "Invalid lure", 400

    redirect_url = lure["redirect_url"]
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    referer = request.headers.get("Referer")

    existing_log = next(
        (
            log
            for log in get_logs()
            if log["ip"] == str(encrypt.encrypt_logs(ip, password))
            and log["user_agent"] == str(encrypt.encrypt_logs(user_agent, password))
            and log["lure"] == str(encrypt.encrypt_logs(key, password))
        ),
        None,
    )

    if existing_log is not None:
        existing_log["count"] += 1
        save_log(existing_log)
    else:
        log = {
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": str(encrypt.encrypt_logs(ip, password)),
            "user_agent": str(encrypt.encrypt_logs(user_agent, password)),
            "country": str(encrypt.encrypt_logs(get_country(ip), password)),
            "referer": str(encrypt.encrypt_logs(referer, password)),
            "redirect_url": str(encrypt.encrypt_logs(redirect_url, password)),
            "count": 1,
            "lure" : str(encrypt.encrypt_logs(key, password)),
        }
        save_log(log)

    return redirect(redirect_url, code=302)


@app.route("/")
def index():
    # Get information from the client's request
    access_time = current_time
    ip = request.remote_addr
    user_agent = request.user_agent.string
    device_type = request.user_agent.platform
    # Use a third-party API to get the country of the IP
    country = get_country(ip)
    # Log the information
    with open("log.txt", "a") as f:
        f.write(f"{access_time} {ip} {user_agent} {device_type} {country}\n")

    return render_template("index.html")

#users = { "admin" : generate_password_hash(password) }

@auth.verify_password
def verify_password(username, password):
    if username in users:
        return username
        


@app.route("/logs")
@auth.login_required
def logs():
    encrypted_logs = get_logs()
    
    try:
        #print("Here")        
        password_d = get_decrypt_password(auth.current_user())
        decrypted_logs = decrypt.decrypt_logs(password_d)

        return render_template("logs.html", logs=decrypted_logs)

    except Exception as e:
        print("Error log:",e)
        return "<h1> Hmm. Something went wrong. Please check the logs!</h1>"

if __name__ == "__main__":
   password = input("Password to encrypt logs with: ")
   users = { "admin" : password }
   app.run(host="0.0.0.0", debug = True)
