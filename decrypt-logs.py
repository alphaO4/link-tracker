import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def decrypt_logs(password):
    with open("encrypted_logs.json", "r") as f:
        encrypted_logs = json.load(f)
    # Hash the password to get a key of the correct length for AES
    hashed_password = SHA256.new(password.encode('utf-8')).digest()
    # Decrypt the encrypted logs using AES in ECB mode
    cipher = AES.new(hashed_password, AES.MODE_ECB)
    padded_logs_json = cipher.decrypt(encrypted_logs)
    # Remove the padding from the logs
    logs_json = padded_logs_json.rstrip(b'\0')
    # Deserialize the logs from a JSON string
    logs = json.loads(logs_json.decode('utf-8'))
# Example usage

passphrase = "secret_pass"
print(decrypt_logs(passphrase))