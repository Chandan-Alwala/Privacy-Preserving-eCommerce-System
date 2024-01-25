import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import random
import hashlib
sha256 = hashlib.sha256()
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

customer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
customer_socket.connect(('localhost', 8000))

#Customer Broker Auth
username = input('Enter your username: ')
password = input('Enter your password: ')

credentials = username + " " + password
customer_socket.send(credentials.encode())
authentication_result = customer_socket.recv(1024).decode()

def init():
    message="Menu"
    customer_socket.send(message.encode())
    menu = customer_socket.recv(1024).decode()
    print(menu)

def unpad_file(file_data):
    idx= max(i for i, byte in enumerate(file_data) if byte != '0')
    unpad_f = file_data[:idx+1]
    return unpad_f

def checkIntegrity(content, integrityCode):
      def_input = content+str(Integrity_key_with_merchant)
      sha256 = hashlib.sha256()
      sha256.update((def_input).encode())
      digest = sha256.hexdigest()
      if(str(digest.strip()) == str(integrityCode.strip()[:64])):
            return True
      return False

def DH_decrypt(encrypted_message, key):
    decrypted_message = ""
    for i in range(len(encrypted_message)):
        decrypted_message += chr(ord(encrypted_message[i]) ^ key)
    return decrypted_message

def receiveFile():
    file_data = customer_socket.recv(1024).decode()
    ack = "received file_data"
    customer_socket.send(ack.encode())
    f = open("receivedFile.txt", "w")
    content, integrityCode = (file_data).split(':')[0].strip(), (file_data).split(':')[1].strip()
    decrypted_content = decrypt_string(content, DH_shared_number_with_merchant)
    unpadded_content = unpad_file(decrypted_content)
    checkIntegrity(decrypted_content, integrityCode)
    print("Integrity check successful")
    f.write(unpadded_content)  
    f.close()
    print("File received from Broker.")

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

def compute_DH_shared_secret(my_DH_private_key, merchant_DH_public_key, p):
    return mod_exp(merchant_DH_public_key, my_DH_private_key, p)


if "Authentication successful" in authentication_result:
    print("User authentication with Broker successful")
    
    broker_public_key = RSA.import_key(open('broker_public_key.pem').read())
    R = os.urandom(16).hex()
    cipher = PKCS1_OAEP.new(broker_public_key)
    encrypted_R = cipher.encrypt(R.encode())
    customer_socket.send(encrypted_R)
    decrypted_R = customer_socket.recv(1024).decode()

    if decrypted_R == R:
        print("Broker authenticated successfully.")
    else:
        print("Broker authentication failed.")
        customer_socket.close()
        exit()

    # DH 
    received_primes = (customer_socket.recv(1024).decode()).split("-")
    p = int(received_primes[0])
    g = int(received_primes[1])
    print(f"received primes p:{p} and g:{g} from broker")

    DH_private_key, DH_public_key = generate_DH_key_pair(p, g)

    customer_socket.send(str(DH_public_key).encode())
    merchant_DH_public_key = int(customer_socket.recv(1024))
    ack = "received merchant_DH_public_key"
    customer_socket.send(ack.encode())

    DH_shared_number_with_merchant = compute_DH_shared_secret(DH_private_key, merchant_DH_public_key, p)
    print(f"computed shared secret is {DH_shared_number_with_merchant}")
    Integrity_key_with_merchant = DH_shared_number_with_merchant + 1

    init()
    funds = 100         
    
    while True:
        message = input("Enter your selection: ")
        if message in ['1', '2', '3', '4']:
            break
        else:
            print("Invalid selection. Please enter valid item number.")

    encrypted_selection = encrypt_string(message, DH_shared_number_with_merchant)
    customer_socket.send((b'selection : '+ encrypted_selection))            
    response = customer_socket.recv(1024).decode()
    print('FROM BROKER: '+ response)  

    while True:
        payment = input('Do you want to pay? (y/n): ')
        if payment.lower() in ['y', 'n']:
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

    customer_socket.send(('pay : '+payment).encode())           
    if payment.lower() == 'y' and (funds-5) >= 0:
            funds-=5
            print('Payment successful. Remaining balance ' + str(funds))
            receiveFile()
            final_ack = customer_socket.recv(1024).decode()
            print(f"final ack: {final_ack}\n")
    else:
            print('Payment cancelled. Either you cancelled or insufficient funds\n')
            response = customer_socket.recv(1024).decode()
else:
    print(authentication_result)
        
customer_socket.close()