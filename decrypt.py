import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

# Add padding to data to align to block boundary
def add_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

# Remove padding from data
def remove_pad(data):
    pad_len = data[-1]
    return data[:-pad_len]

class Decrypt():
    def get_logs():
        try:
            with open("out-decrypted.json", "r") as f:
                logs = json.load(f)
            return logs
        except:
            return []

    def decrypt_logs(passphrase):
        with open("log.json", "r") as f:
            encrypted_logs = json.load(f)

        # Hash the password to get a key of the correct length for AES
        hashed_password = SHA256.new(passphrase.encode("utf-8")).digest()

        # Decrypt the encrypted logs using AES in ECB mode
        decrypted_logs = []
        for log in encrypted_logs:
            decrypted_log = {}
            for field in log:
                if field in ["time", "count"]:
                    decrypted_log[field] = log[field]
                else:
                    encrypted_field = base64.b64decode(log[field].encode("utf-8"))
                    cipher = AES.new(hashed_password, AES.MODE_ECB)
                    decrypted_field = remove_pad(cipher.decrypt(encrypted_field))
                    decrypted_log[field] = decrypted_field.decode("utf-8")

            decrypted_logs.append(decrypted_log)

        # Write the decrypted logs to a file
            logs = Decrypt.get_logs()
            logs.append(decrypted_logs)
            with open("out-decrypted.json", "w") as f:
                json.dump(decrypted_logs, f, indent=4)

        return decrypted_logs


# Example usage
passphrase = input("What passphrase was used for this log? ")
Decrypt.decrypt_logs(passphrase)
