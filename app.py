from flask import Flask, request, render_template, redirect
import requests
import hashlib
import json
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_lures():
    try:
        with open("lures.json", "r") as f:
            return json.load(f)
    except:
        return []

lures = load_lures()

def save_lures(lures):
    with open("lures.json", "w") as f:
        json.dump(lures, f)

def get_country(ip):
    #get the api key from https://ipgeolocation.io/ and put it into .env file
    API_KEY = os.getenv('API_KEY')
    response = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}')
    data = response.json()
    try:
        country = data['country_name']
    except:
        country = data['message']
    return country

def create_lure(redirect_url):
    unique_key = hashlib.sha256(str(datetime.datetime.now().microsecond).encode()).hexdigest()[:6]
    lure = {'id': unique_key, 'redirect_url': redirect_url}
    lures.append(lure)
    save_lures(lures)
    return unique_key

def get_logs():
    try:
        with open('log.json', 'r') as f:
            logs = json.load(f)
        return logs
    except:
        return []

def save_log(log):
    logs = get_logs()
    logs.append(log)
    with open("log.json", "w") as f:
        json.dump(logs, f)

@app.route("/add-lure", methods=["GET", "POST"])
def add_lure():
    if request.method == "POST":
        redirect_url = request.form.get("redirect_url")
        if not redirect_url:
            return "Redirect URL is required", 400
        if not redirect_url.startswith("http://") and not redirect_url.startswith("https://"):
            redirect_url = "https://" + redirect_url
        key = create_lure(redirect_url)
        return f"Lure created: {request.host}/lure/{key}"

    return render_template("add_lure.html")


@app.route("/lure/<key>")
def lure(key):
    lure = next((l for l in lures if l['id'] == key), None)
    if lure is None:
        return "Invalid lure", 400

    redirect_url = lure['redirect_url']
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    referer = request.headers.get("Referer")

    existing_log = next((log for log in get_logs() if log['ip'] == ip and log['user_agent'] == user_agent), None)

    if existing_log is not None:
        existing_log['count'] += 1
        save_log(log)
    else:
        log = {
            'time': current_time,
            'ip': ip,
            'user_agent': user_agent,
            'country': get_country(ip),
            'referer': referer,
            'redirect_url': redirect_url,
            'count': 1
        }
        save_log(log)

    return redirect(redirect_url, code=302)


@app.route('/')
def index():
    # Get information from the client's request
    access_time = current_time
    ip = request.remote_addr
    user_agent = request.user_agent.string
    device_type = request.user_agent.platform
    # Use a third-party API to get the country of the IP
    country = get_country(ip)
    # Log the information
    with open('log.txt', 'a') as f:
        f.write(f'{access_time} {ip} {user_agent} {device_type} {country}\n')

    return render_template('index.html')

@app.route('/logs')
def logs():
    logs = get_logs()
    return render_template('logs.html', logs=logs)

@app.route('/<lure_id>')
def track(lure_id):
    log = {
        'ip': request.remote_addr,
        'access_time': str(current_time),
        'user_agent': request.user_agent.string,
        'country': get_country(request.remote_addr)
    }
    with open('logs.json', 'r') as f:
        logs = json.load(f)
    logs.append(log)
    with open('logs.json', 'w') as f:
        json.dump(logs, f)
    return redirect(lures[lure_id]['redirect_url'], code=302)

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
