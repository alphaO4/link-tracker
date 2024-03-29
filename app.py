from flask import Flask, request, render_template, redirect, jsonify
import requests
import hashlib
import datetime
import os
from dotenv import load_dotenv, find_dotenv
from flask_httpauth import HTTPBasicAuth
import sqlite3
import requests
import base64
import json
from cryptography.fernet import Fernet
from time import sleep


password_g = Fernet.generate_key()
app = Flask(__name__)
auth = HTTPBasicAuth()
load_dotenv(find_dotenv())


#decrypt


#Set base64 to encode
encode = base64.b64encode

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
    device_type TEXT,
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
    counting INTEGER,
    lure TEXT,
    identifier TEXT,
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
    result_dict = {}
    cursor.execute("SELECT time, ip, user_agent, country, referer, redirect_url, counting, lure FROM catchlogs")
    # get the column names
    columns = [col[0] for col in cursor.description]

    # fetch all rows and convert to dictionary
    result = []
    for row in cursor.fetchall():
        row_dict = {}
        for i, value in enumerate(row):
            row_dict[columns[i]] = value
        result.append(row_dict)
    return result

def save_log(log):

    cursor.execute("SELECT counting FROM catchlogs WHERE identifier=?", (str(log["identifier"]),))
    counting = cursor.fetchone()
    print("Counting: " + str(counting))
    if counting is not None:
        print("Counting: " + str(counting[0]))
        cursor.execute(
            "UPDATE catchlogs SET counting=? WHERE identifier=?", (counting[0] + 1, str(log["identifier"]),),
        )
    else:
        cursor.execute(
            "INSERT INTO catchlogs (time, ip, user_agent, country, referer, redirect_url, counting, lure, identifier) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                log["time"],
                log["ip"],
                log["user_agent"],
                log["country"],
                log["referer"],
                log["redirect_url"],
                log["counting"],
                log["lure"],
                log["identifier"],
            ),
        )
    conn.commit()

@app.route("/add-lure", methods=["GET", "POST"])
@auth.login_required
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
    if request.headers.get("Referer") is None:
        referer = ""
    else:
        referer = request.headers.get("Referer")
    log = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": fernet.encrypt(ip.encode("utf-8")),
        "user_agent": fernet.encrypt(user_agent.encode("utf-8")),
        "country": fernet.encrypt(get_country(ip).encode("utf-8")),
        "redirect_url": fernet.encrypt(redirect_url.encode("utf-8")),
        "referer": fernet.encrypt(referer.encode("utf-8")),
        "counting": 1,
        "lure": fernet.encrypt(key.encode("utf-8")),
        "identifier": hashlib.sha256(ip.encode("utf-8")+key.encode("utf-8")).hexdigest(),
    }
    save_log(log)

    return redirect(redirect_url, code=302)

@app.route("/")
@auth.login_required
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
    if username == 'admin' and password_g.decode("utf-8") == password:
        return True


@app.route("/logs")
@auth.login_required
def logs():
    encrypted_logs = get_logs()
    decrypted_logs=[]
    for log in encrypted_logs:
        decrypted_log = {}
        for field in log:
            if field in ["time", "counting"]:
                decrypted_log[field] = log[field]
            else:
                # print(field)
                # print(log[field])
                decrypted_log[field] = fernet.decrypt(log[field]).decode("utf-8")
                # print("Decrypted: " + decrypted_log[field])
        decrypted_logs.append(decrypted_log)
    #print("Decrypted_logs:",decrypted_logs)
    return render_template("logs.html", logs=decrypted_logs)


if __name__ == "__main__":
    print("Password: " + password_g.decode("utf-8") + " (Save this password for decrypting the logs)")
    fernet = Fernet(password_g)
    users = {"admin": fernet}
    app.run(host="0.0.0.0", debug=True, port=8080)
