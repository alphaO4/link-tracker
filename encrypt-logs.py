import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def encrypt_logs(logs, passphrase):
    # Hash the password to get a key of the correct length for AES
    hashed_password = SHA256.new(passphrase.encode('utf-8')).digest()
    # Serialize the logs to a JSON string
    logs_json = json.dumps(logs).encode('utf-8')
    # Pad the logs to a multiple of 16 bytes for AES
    padded_logs_json = logs_json + (16 - len(logs_json) % 16) * b'\0'
    # Encrypt the padded logs using AES in ECB mode
    cipher = AES.new(hashed_password, AES.MODE_ECB)
    encrypted_logs = cipher.encrypt(padded_logs_json)
    with open("encrypted_logs.json", "w") as f:
        json.dump(encrypted_logs, f)

# Example usage
logs = [{"ip": "192.168.1.1", "time": "2022-01-01T12:00:00", "user_agent": "Mozilla/5.0", 
         "country": "US", "referer": "https://example.com", "redirect_url": "https://redirect.com"}, 
        {"ip": "192.168.1.2", "time": "2022-01-01T12:01:00", "user_agent": "Chrome/80.0", 
         "country": "UK", "referer": "https://example.com", "redirect_url": "https://redirect.com"}]
passphrase = "1234"
encrypt_logs(logs, passphrase)
