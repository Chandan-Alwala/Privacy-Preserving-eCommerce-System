import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
from ftplib import FTP
import random
import hashlib
sha256 = hashlib.sha256()
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
merchant_socket.bind(('localhost', 8100))
merchant_socket.listen(2)

print("Merchant is listening on port 8100...")

funds = 100
requests = {}

def get_menu():
    try:
        menu = ""
        name = os.listdir("Menu")
        for i,n in enumerate(name):
            menu += "\n" + str(i+1) + ". " + n 
        return menu
    except Exception as e:
            print(f"An error occurred: {e}")

menu = get_menu()


while True:
    message = input("Do you want to add or remove files? (Enter: add/remove/no): ")
    message = message.lower()
    if message == 'add':
        try:
            file_name = input("Enter file name: ")
            if file_name in menu:
                print(f"Error: File '{file_name}' already exists. Please choose a different name.")
            else:
                file_content = input("Enter file content: ")
                with open(f"Menu/{file_name}.txt", "w") as f:
                    f.write(file_content)
                print("New file created")
                menu = get_menu()
                print(f"Menu updated: {menu}")
        except Exception as e:
            print(f"An error occurred: {e}")
    elif message == 'remove':
        try:
            file_to_remove = input("Enter the file name to remove: ")
            file_path = f"Menu/{file_to_remove}.txt"
            try:
                os.remove(file_path)
                print(f"File '{file_to_remove}' removed from the filesystem")
            except FileNotFoundError:
                print(f"Error: File '{file_to_remove}' not found in the filesystem.")    
            menu = get_menu()
            print(f"Menu updated: {menu}")
        except Exception as e:
            print(f"An error occurred: {e}")
    elif message == 'no':
        print("Waiting for broker to connect")
        break
    else:
        print("Invalid input. Please enter 'add' or 'remove' or 'no'.")
   


conn, addr = merchant_socket.accept()

def pad_data(data, size):
    if len(data) < size:
        pad_f = data.ljust(size, '0')
    else:
        pad_f = data
    return pad_f 

def sendFile(selection, requestNo):
    file_list = os.listdir("Menu")
    file_path = f"Menu/{file_list[int(selection)-1]}"
    f = open(file_path, "r")
    data = f.read()
    f.close()
    padded_data = pad_data(data, 300)
    encrypted_data = encrypt_string(padded_data, requests[requestNo][2])
    integritycheck = generateIntegrityCheckCode(data)
    to_be_sent = encrypted_data + b":"+ (str(integritycheck).encode())
    conn.send(to_be_sent)
    print('Delivered - Transaction complete\n')

def generateIntegrityCheckCode(content):
    def_input = content+str(Integrity_key_with_customer)
    sha256 = hashlib.sha256()
    sha256.update((def_input).encode())
    digest = sha256.hexdigest()
    return digest

# encryption and decryption with keyed-hash
def xor_with_digest(plaintext, hash_digest):
    if len(hash_digest) == 0:
        print("Hash digest must not be empty")
    block_size = min(len(plaintext), len(hash_digest))
    result = bytes([p_byte ^ h_byte for p_byte, h_byte in zip(plaintext[:block_size], hash_digest)])
    return result
  
def encrypt(plaintext, key):
  iv = '0'
  ciphertext = ''
  for p in plaintext:
    b = hashlib.sha256((str(key)+""+iv).encode()).digest()
    ciphertext += (xor_with_digest(p.encode(), b)).decode()
  return ciphertext.replace("\n", " ")

def decrypt(ciphertext, key):
  iv = '0'
  plaintext = ''
  for c in ciphertext:
    b = hashlib.sha256((str(key)+""+iv).encode()).digest()
    plaintext += (xor_with_digest(c.encode(), b)).decode()
  return plaintext.replace("\n", " ")

def generate_key(password_provided):
  password = password_provided.encode()
  salt = b'salt_'
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend())
  key = base64.urlsafe_b64encode(kdf.derive(password))
  return key

def encrypt_string(data, key):
    key = generate_key(str(key))
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data

def decrypt_string(encrypted_data, key):
    key = generate_key(str(key))
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()

# DH
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp // 2
        base = (base * base) % mod
    return result

def generate_DH_key_pair(p, g):
    DH_private_key = random.randint(2, p - 2)
    DH_public_key = mod_exp(g, DH_private_key, p)
    return DH_private_key, DH_public_key

def compute_DH_shared_secret(my_DH_private_key, customer_DH_public_key, p):
    return mod_exp(customer_DH_public_key, my_DH_private_key, p)

#Merchant Broker Auth
merchant_private_key = RSA.import_key(open('merchant_private_key.pem').read())
encrypted_R1 = conn.recv(1024)
cipher = PKCS1_OAEP.new(merchant_private_key)
decrypted_R1 = cipher.decrypt(encrypted_R1).decode()
conn.send(decrypted_R1.encode())

broker_public_key = RSA.import_key(open('broker_public_key.pem').read())
R2 = os.urandom(16).hex()
cipher = PKCS1_OAEP.new(broker_public_key)
encrypted_R2 = cipher.encrypt(R2.encode())
conn.send(encrypted_R2)
decrypted_R2 = conn.recv(1024).decode()

if decrypted_R2 == R2:
    print("Broker authenticated successfully.")
else:
    print("Broker authentication failed.")

if decrypted_R2 == R2:
    while True:
        message=conn.recv(1024).decode()
        response = ""

        if 'DH' in message:
            received_primes = message.split("-")
            p = int(received_primes[0])
            g = int(received_primes[1])
            print(f"received primes p:{p} and g:{g} from broker")

            DH_private_key, DH_public_key = generate_DH_key_pair(p, g)
            conn.send(str(DH_public_key).encode())

        elif 'customer_secret' in message: 
            customer_DH_public_key = int(message.split("-")[0])
            counter = message.split("-")[1]
            ack = "received customer_DH_public_key"
            conn.send(ack.encode())

            DH_shared_number_with_customer = compute_DH_shared_secret(DH_private_key, customer_DH_public_key, p)
            print(f"computed shared secret is {DH_shared_number_with_customer}")
            requests["R"+counter] = ["", "", DH_shared_number_with_customer]
            Integrity_key_with_customer = DH_shared_number_with_customer + 1

        elif 'Menu' in message:
            print('FROM BROKER: Send Menu')
            response = get_menu()
            conn.send(response.encode())
            print("Sent Menu...")

        elif 'selection' in message:
            print('FROM BROKER: Send Selection')
            requestNo = message.split('-')[0].strip()
            selection = message.split(':')[1].strip()
            decrypted_selection = decrypt_string(selection, requests[requestNo][2])
            print(f"selected item: {decrypted_selection}")
            requests[requestNo][0] = decrypted_selection
            requests[requestNo][1] = False
            response = "Pay to deliver"
            conn.send(response.encode())
            print("awaiting payment", response)

        elif 'pay' in message:
            requestNo = message.split('-')[0].strip()
            print('FROM BROKER: '+ requestNo +' Payment Status - ' + message.split(':')[1])

            if eval(message.split(':')[1]):
                funds+=5
                print('Payment Successful')
                print('Total funds '+ str(funds))
                print("Initiating file transfer...")
                sendFile(requests[requestNo][0], requestNo)
                requests[requestNo][1] = True
            else:
                print('Payment NOT successful\n')
                ack = "Payment unsuccessful"
                conn.send(ack.encode())

