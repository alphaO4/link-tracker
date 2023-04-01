import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
from Crypto.Util.Padding import unpad


class decrypt():
    def decrypt_logs(encoded_encrypted_logs, encoded_nonce, passphrase):
        # Hash the password to get a key of the correct length for AES
        hashed_password = SHA256.new(passphrase.encode("utf-8")).digest()

        # Decode the base64-encoded nonce and encrypted logs
        nonce = base64.b64decode(encoded_nonce)
        encrypted_logs = base64.b64decode(encoded_encrypted_logs)

        # Decrypt the encrypted logs using AES in GCM mode
        cipher = AES.new(hashed_password, AES.MODE_GCM, nonce=nonce)
        decrypted_logs_json = cipher.decrypt(encrypted_logs)

        # Unpad and decode the JSON string
        decrypted_logs_json = decrypted_logs_json.decode("utf-8")
        decrypted_logs = json.loads(decrypted_logs_json)

        return decrypted_logs



# Example usage
if __name__ == "__main__": 
    passphrase = input("Passphrase used: ")
    enlogs = [
        {"field0": "oan+ZJ+wF/p67zeKjveO2Q==", "field1": "E5f5To/i9S9vU0IKWTW8Iw==", "field2": "zv7VW5+QH5J5Y5SjaaZnVg==", "field3": "u4sc4+DysytWllM/LICj7g==", "field4": "VWfpycR+Mrwrbkl2Q+/Ftw==", "field5": "sucYXs2jKzxdF/ggLaJe+g==", "field6": "y0KjEzrHJrNU0r/vgMY+tQ=="}
    ]
    print(decrypt.decrypt_logs(passphrase, enlogs))
