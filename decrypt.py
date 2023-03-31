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


#passphrase = input("Passphrase used ")


class decrypt():

    def decrypt_logs(passphrase, enlogs):
        encrypted_logs = enlogs

        print("Passwort: " + passphrase)
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
                    encrypted_field = base64.b64decode(log[field])
                    cipher = AES.new(hashed_password, AES.MODE_ECB)
                    decrypted_field = remove_pad(cipher.decrypt(encrypted_field))
                    decrypted_log[field] = decrypted_field.decode("utf-8")

            decrypted_logs.append(decrypted_log)

        return decrypted_logs


# Example usage
if __name__ == "__main__": 
    passphrase = input("Passphrase used: ")
    print(decrypt.decrypt_logs(passphrase))
