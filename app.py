from flask import Flask, request, render_template, redirect, jsonify
import requests
import hashlib
import json
import datetime
import os
from dotenv import load_dotenv, find_dotenv
from encrypt import encrypt
from decrypt import decrypt
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests


password = ""
app = Flask(__name__)
auth = HTTPBasicAuth()
load_dotenv(find_dotenv())

api_key = os.getenv("API_KEY")
print("Api Key " + str(api_key))
# users = { "admin" : generate_password_hash(password) }



# Connect to the database
conn = sqlite3.connect("link-tracker.db", check_same_thread=False)
cursor = conn.cursor()

# Create the table to store lures
cursor.execute(
    """CREATE TABLE IF NOT EXISTS lures (
    id INTEGER,
    unique_key TEXT,
    redirect_url TEXT,
    PRIMARY KEY("id" AUTOINCREMENT)

)"""
)
conn.commit()

# Create the table to store access logs
cursor.execute(
    """CREATE TABLE IF NOT EXISTS accesslogs (
    id INTEGER,
    access_time TEXT,
    ip TEXT,
    user_agent TEXT,
    device_typ TEXT,
    country TEXT,
    PRIMARY KEY("id" AUTOINCREMENT)
)"""
)
conn.commit()

# Create the table to store catch logs
cursor.execute(
    """CREATE TABLE IF NOT EXISTS catchlogs (
    id INTEGER,
    time TEXT,
    ip TEXT,
    user_agent TEXT,
    country TEXT,
    referer TEXT,
    redirect_url TEXT,
    count INTEGER,
    lure TEXT,
    PRIMARY KEY("id" AUTOINCREMENT)
)"""
)
conn.commit()



def load_lures():
    cursor.execute("SELECT * FROM lures")
    lures = cursor.fetchall()
    print(lures)
    return lures


lures = load_lures()


def get_decrypt_password(username):
    for user, password in users.items():
        if user == username:
            return password
    return None


def get_country(ip):
    # get the api key from https://ipgeolocation.io/ and put it into a .env file
    API_KEY = os.getenv("API_KEY")
    print("Api Key " + str(API_KEY))
    response = requests.get(
        f"https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}"
    )
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
    cursor.execute("INSERT INTO lures (unique_key,redirect_url) VALUES (?, ?)", (str(unique_key), str(redirect_url)))
    conn.commit()
    return unique_key

def get_logs():
    cursor.execute("SELECT * FROM catchlogs")
    logs = cursor.fetchall()
    return logs

def save_log(log):
    cursor.execute("SELECT count FROM catchlogs WHERE ip=? AND user_agent=?", (log["ip"], log["user_agent"]))
    count = cursor.fetchone()
    if count is not None:
        cursor.execute(
            "UPDATE catchlogs SET count=? WHERE ip=? AND user_agent=?",
            (count[0] + 1, log["ip"], log["user_agent"]),
        )
    else:
        cursor.execute(
            "INSERT INTO catchlogs (time, ip, user_agent, country, referer, redirect_url, count, lure) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                log["time"],
                log["ip"],
                log["user_agent"],
                log["country"],
                log["referer"],
                log["redirect_url"],
                log["count"],
                log["lure"],
            ),
        )
    conn.commit()

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
@app.route("/link/<key>")
def lure(key):
    #get the lure from the database
    cursor.execute("SELECT * FROM lures WHERE unique_key=?", (key,))
    lure = cursor.fetchone()
    print(lure)
    if lure is None:
        return "Invalid lure", 400

    redirect_url = lure[2]
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    referer = request.headers.get("Referer")
    log = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": str(encrypt.encrypt_logs(ip, password)),
        "user_agent": str(encrypt.encrypt_logs(user_agent, password)),
        "country": str(encrypt.encrypt_logs(get_country(ip), password)),
        "referer": str(encrypt.encrypt_logs(referer, password)),
        "redirect_url": str(encrypt.encrypt_logs(redirect_url, password)),
        "count": 1,
        "lure": str(encrypt.encrypt_logs(key, password)),
    }
    save_log(log)

    return redirect(redirect_url, code=302)


@app.route("/")
def index():
    # Get information from the client's request
    access_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr
    user_agent = request.user_agent.string
    device_type = request.user_agent.platform
    # Use a third-party API to get the country of the IP
    country = get_country(ip)
    # Log the information
    cursor.execute(
        "INSERT INTO accesslogs (access_time, ip, user_agent, device_type, country) VALUES (?, ?, ?, ?, ?)",
        (access_time, ip, user_agent, device_type, country),
    )
    conn.commit()
    return render_template("index.html")


@auth.verify_password
def verify_password(username, password):
    if username in users:
        return username


@app.route("/logs")
@auth.login_required
def logs():
    encrypted_logs = get_logs()

    try:
        # print("Here")
        password_d = get_decrypt_password(auth.current_user())
        decrypted_logs = decrypt.decrypt_logs(password_d)

        return render_template("logs.html", logs=decrypted_logs)

    except Exception as e:
        print("Error log:", e)
        return "<h1> Hmm. Something went wrong. Please check the logs!</h1>"


if __name__ == "__main__":
    password = input("Password to encrypt logs with: ")
    users = {"admin": password}
    app.run(host="0.0.0.0", debug=True)
