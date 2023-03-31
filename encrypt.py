import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

# Add padding to data to align to block boundary
def add_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

class encrypt():
    def encrypt_logs(logs, passphrase):
        # Hash the password to get a key of the correct length for AES
        hashed_password = SHA256.new(passphrase.encode("utf-8")).digest()
        # Serialize the logs to a JSON string
        logs_json = json.dumps(logs).encode("utf-8")
        print("logs-json:", logs_json)
        print("logs-raw:", logs)
        # Pad the logs to a multiple of 16 bytes for AES
        padded_logs_json = add_pad(logs_json)
        # Encrypt the padded logs using AES in ECB mode
        cipher = AES.new(hashed_password, AES.MODE_ECB)
        encrypted_logs = cipher.encrypt(padded_logs_json)
        # Encode the encrypted logs to base64
        encoded_encrypted_logs = base64.b64encode(str(encrypted_logs).encode("utf-8"))
        return encoded_encrypted_logs

# Example usage
#logs = [{"ip": "192.168.1.1", "time": "2022-01-01T12:00:00", "user_agent": "Mozilla/5.0", 
#        "country": "US", "referer": "https://example.com", "redirect_url": "https://redirect.com"}]
#passphrase = "1234"
#encoded_encrypted_logs = encrypt.encrypt_logs(logs, passphrase)
#print(encoded_encrypted_logs)
