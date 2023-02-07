import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

passphrase = '1234'
class decrypt:
    def decrypt_logs2(passphrase):
        with open("log.json", "r") as f:
            encrypted_logs = json.load(f)
        # Hash the password to get a key of the correct length for AES
        hashed_password = SHA256.new(passphrase.encode('utf-8')).digest()
        # Decrypt the encrypted logs using AES in ECB mode
        cipher = AES.new(hashed_password, AES.MODE_ECB)
        padded_logs_json = cipher.rstrip(b'\0')
        # Remove the padding from the logs
        logs_json = padded_logs_json.decrypt(encrypted_logs)
        # Deserialize the logs from a JSON string
        logs = json.loads(logs_json.decode('utf-8'))
        return logs
    
    @staticmethod
    def decrypt_log_entry(passphrase, encrypted_log_entry):
        # Split the encrypted log entry into the unencrypted identifier and encrypted data
        identifier, encrypted_data = encrypted_log_entry.split(b' ', 1)
        print(encrypted_data)
        # Hash the password to get a key of the correct length for AES
        hashed_password = SHA256.new(passphrase.encode('utf-8')).digest()
        # Decrypt the encrypted data using AES in ECB mode
        cipher = AES.new(hashed_password, AES.MODE_ECB)
        padded_log_data = cipher.decrypt(encrypted_data)
        # Remove the padding from the log data
        log_data = padded_log_data.rstrip(b'\0')
        # Deserialize the log data from a JSON string
        log = json.loads(log_data.decode('utf-8'))
        return identifier, log
    
    @staticmethod
    def decrypt_logs(passphrase):
        logs = []
        with open("log.json", "rb") as f:
            encrypted_logs = f.readlines()
        for encrypted_log_entry in encrypted_logs:
            identifier, log = decrypt.decrypt_log_entry(passphrase, encrypted_log_entry)
            logs.append((identifier, log))
        return logs



# Example usage
print(decrypt.decrypt_logs(passphrase))