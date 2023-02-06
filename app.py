from flask import Flask, request, render_template
import requests

app = Flask(__name__)

@app.route('/')
def index():
    # Get information from the client's request
    access_time = request.remote_addr
    ip = request.remote_addr
    user_agent = request.user_agent.string
    device_type = request.user_agent.platform
    # Use a third-party API to get the country of the IP
    response = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}')
    data = response.json()
    country = data['country_name']

    # Log the information
    with open('log.txt', 'a') as f:
        f.write(f'{access_time} {ip} {user_agent} {device_type} {country}\n')

    return render_template('index.html', access_time=access_time, ip=ip, user_agent=user_agent, device_type=device_type, country=country)

if __name__ == '__main__':
    app.run()
