import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def encrypt_logs(logs, password):
    # Hash the password to get a key of the correct length for AES
    hashed_password = SHA256.new(password.encode('utf-8')).digest()
    # Serialize the logs to a JSON string
    logs_json = json.dumps(logs).encode('utf-8')
    # Pad the logs to a multiple of 16 bytes for AES
    padded_logs_json = logs_json + (16 - len(logs_json) % 16) * b'\0'
    # Encrypt the padded logs using AES in ECB mode
    cipher = AES.new(hashed_password, AES.MODE_ECB)
    encrypted_logs = cipher.encrypt(padded_logs_json)
    return encrypted_logs

def decrypt_logs(encrypted_logs, password):
    # Hash the password to get a key of the correct length for AES
    hashed_password = SHA256.new(password.encode('utf-8')).digest()
    # Decrypt the encrypted logs using AES in ECB mode
    cipher = AES.new(hashed_password, AES.MODE_ECB)
    padded_logs_json = cipher.decrypt(encrypted_logs)
    # Remove the padding from the logs
    logs_json = padded_logs_json.rstrip(b'\0')
    # Deserialize the logs from a JSON string
    logs = json.loads(logs_json.decode('utf-8'))
    return logs


LOGS = [{"ip": "192.168.1.1", "time": "2022-01-01T12:00:00", "user_agent": "Mozilla/5.0", "country": "US", "referer": "https://example.com", "redirect_url": "https://redirect.com"}]
enc = encrypt_logs(LOGS,'1234')
print("Encrypted: ")
print(LOGS)
dec = decrypt_logs(enc, '1234')
print("Decrypted:")
print(dec)