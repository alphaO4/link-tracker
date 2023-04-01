import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

# Add padding to data to align to block boundary
def add_pad(data, block_size=16):
    if data is None:
        padded_data = pad("None".encode("utf-8"), block_size)
    else:
        padded_data = pad(data.encode("utf-8"), block_size)
    return padded_data

class encrypt():
    def encrypt_logs(logs, passphrase):
        # Hash the password to get a key of the correct length for AES
        hashed_password = SHA256.new(passphrase.encode("utf-8")).digest()

        # Convert the logs to a JSON string and pad it
        logs_json = json.dumps(logs)
        padded_logs_json = add_pad(logs_json)

        # Generate a random nonce for GCM mode
        nonce = get_random_bytes(12)

        # Encrypt the padded logs using AES in GCM mode
        cipher = AES.new(hashed_password, AES.MODE_GCM, nonce=nonce)
        encrypted_logs = cipher.encrypt(padded_logs_json)

        # Encode the encrypted logs and nonce to base64
        encoded_encrypted_logs = base64.b64encode(encrypted_logs).decode("utf-8")
        encoded_nonce = base64.b64encode(nonce).decode("utf-8")

        return str(encoded_encrypted_logs), str(encoded_nonce)

# Example usage

if __name__ == "__main__": 
    logs = [{"ip": "192.168.1.1", "time": "2022-01-01T12:00:00", "user_agent": "Mozilla/5.0", 
            "country": "US", "referer": "https://example.com", "redirect_url": "https://redirect.com"}]
    passphrase = "1234"
    enc = encrypt()
    encoded_encrypted_logs, encoded_nonce = enc.encrypt_logs(logs, passphrase)
    print(encoded_encrypted_logs)
    print(encoded_nonce)
