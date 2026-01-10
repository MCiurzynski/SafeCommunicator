from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from flask import current_app

def encrypt_totp_secret(totp_secret):
    key = bytes.fromhex(current_app.config['TOTP_ENCRYPTION_KEY'])
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(totp_secret.encode('utf_8'))
    combined = nonce + tag + ciphertext
    
    return base64.b64encode(combined).decode('utf-8')

def decrypt_totp_secret(encrypted_totp_secret):
    key = bytes.fromhex(current_app.config['TOTP_ENCRYPTION_KEY'])
    try:
        data = base64.b64decode(encrypted_totp_secret)
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return decrypted_data.decode('utf-8')
        
    except (ValueError, KeyError) as e:
        print(e)
        return None