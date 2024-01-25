import socket
from ftplib import FTP
import os
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime

counter = 0
customerRequestNumber = {}

def mediateFileTransfer(conn):
    file_data = merchant_socket.recv(1024)
    conn.send(file_data)
    ack = conn.recv(1024).decode()
    print(f"Acknowledgement: {ack}")

def handleRequest(data, conn, counter):
    if 'Menu' in data:
        merchant_socket.send(data.encode())
        menu_response = merchant_socket.recv(1024).decode()
        print('Received Menu, forwarding to customer')
        return menu_response
    
    elif 'selection' in data:
        merchant_socket.send((customerRequestNumber[counter]+' - '+data).encode())
        selection_response = merchant_socket.recv(1024).decode()
        return selection_response
    
    elif 'pay' in data:
        authorized = False
        if data.split(':')[1].strip() == 'y':
            authorized = True
            print('Payment Authorized')
            merchant_socket.send((customerRequestNumber[counter] + ' - pay : ' +str(authorized)).encode())
            mediateFileTransfer(conn)
            return "done"
        else:
            merchant_socket.send(('pay : ' + str(authorized)).encode())
            print('Cancelling Transaction')
            payment_cancel_response = merchant_socket.recv(1024).decode()
            return payment_cancel_response
    return "error"

def authenticate_customer(username, password):
    with open("customer_credentials.txt", "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split()
            if username == stored_username and password == stored_password:
                return True
    return False

def handle_client(conn, addr, counter):
    print("Connected by customer id: ", counter)

    #Authenticate the customer 
    try:
        credentials = conn.recv(1024).decode()
        username, password = credentials.split()
        
        if authenticate_customer(username, password):
            print(f"Customer {counter} authenticated successfully!")
            response = "Authentication successful."
            conn.send(response.encode())
        else:
            print(f"Authentication failed for Customer {counter}")
            response = "Authentication failed. Closing connection."
            conn.send(response.encode())
            conn.close()
            return
    except (ConnectionResetError, ConnectionAbortedError, OSError) as ce:
        print('Customer', counter, 'closed connection')
        return
    
    broker_private_key = RSA.import_key(open('broker_private_key.pem').read())
    encrypted_R = conn.recv(1024)
    cipher = PKCS1_OAEP.new(broker_private_key)
    decrypted_R = cipher.decrypt(encrypted_R).decode()
    conn.send(decrypted_R.encode())

    # DH
    print("Sending primes to customer and merchant")
    prime_p = str(getPrime(15))
    generator_g = str(getPrime(15)) 
    merchant_socket.send((prime_p + "-" + generator_g + "-" + "DH").encode())
    merchant_DH_public_key = merchant_socket.recv(1024).decode()
    conn.send((prime_p + "-" + generator_g).encode())
    customer_DH_public_key = conn.recv(1024).decode()

    print(f"Sent primes p:{prime_p} and g:{generator_g} to merchant and customer")

    merchant_socket.send((customer_DH_public_key + "-" + str(counter) + "-" + "customer_secret").encode())
    merchant_socket.recv(1024).decode()

    conn.send(merchant_DH_public_key.encode())
    conn.recv(1024).decode()


    while True:
        try:
            data = conn.recv(1024).decode()

            if not data:
                print('Transaction Done\n')
                break

            print('FROM CUSTOMER' + str(counter)+': ', data[:13])
            customerRequestNumber[counter] = 'R'+str(counter)
            response = handleRequest(data, conn, counter)
            print(f"response from the merchant is: {response}")
            if 'error' in response:
                print('error here')
            conn.send(response.encode())
            print("response sent to client")
        except (ConnectionResetError, ConnectionAbortedError) as ce:
            print('Customer'+str(counter)+' closed connection\n')
            break

broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
broker_socket.bind(('localhost', 8000))
broker_socket.listen(5)  # Maximum 5 queued connections
print("Broker is listening on port 8000...")

merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
merchant_socket.connect(('localhost', 8100))

#Broker Merchant Auth
merchant_public_key = RSA.import_key(open('merchant_public_key.pem').read())
R1 = os.urandom(16).hex()
cipher = PKCS1_OAEP.new(merchant_public_key)
encrypted_R1 = cipher.encrypt(R1.encode())
merchant_socket.send(encrypted_R1)
decrypted_R1 = merchant_socket.recv(1024).decode()

if decrypted_R1 == R1:
    print("Merchant authenticated successfully.")
else:
    print("Merchant authentication failed.")

broker_private_key = RSA.import_key(open('broker_private_key.pem').read())
encrypted_R2 = merchant_socket.recv(1024)
cipher = PKCS1_OAEP.new(broker_private_key)
decrypted_R2 = cipher.decrypt(encrypted_R2).decode()
merchant_socket.send(decrypted_R2.encode())

if decrypted_R1 == R1:
    while True:
        conn, addr = broker_socket.accept()
        counter += 1
        threading.Thread(target=handle_client, args=(conn, addr, counter)).start()
