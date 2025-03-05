import socket
import threading
import datetime
import random
import os
import time
from math import gcd
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
import argparse

HOST = '127.0.0.1'
PORT = 9000

# Store session keys for each patient
patient_session_keys = {}

# Generate a large prime p and find a generator g in Z*_p
def generate_prime_and_generator():
    parameters = dh.generate_parameters(generator=2, key_size=512)
    p = parameters.parameter_numbers().p  # Large prime
    g = find_generator(p)  # Find a valid generator g
    return p, g

# Find a valid generator g in Z*_p
def find_generator(p):
    for g in range(2, p - 1):
        if pow(g, (p - 1) // 2, p) != 1:  # Basic check for primitive root
            return g
    return 2  # Fallback

# Generate ElGamal key pair (p, g, y) and private key x
def generate_elgamal_keys():
    p, g = generate_prime_and_generator()
    x = random.randint(2, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y), x  # Public key tuple (p, g, y) and private key x

# Encrypt session key using patient's public key
def encrypt_session_key(msg, public_key):
    p, g, y = public_key
    
    # Convert message to integer if it's bytes
    if isinstance(msg, bytes):
        msg = int.from_bytes(msg, byteorder='big')
    
    # Choose a random ephemeral key k
    k = random.randint(2, p - 2)
    
    # Compute ciphertext
    c1 = pow(g, k, p)
    c2 = (msg * pow(y, k, p)) % p
    
    return c1, c2

def decrypt_session_key(cipher_msg, private_key, p):
    c1, c2 = cipher_msg
    
    # Compute s = c1^x mod p
    s = pow(c1, private_key, p)
    
    # Compute s^(-1) mod p (modular inverse)
    s_inv = pow(s, p - 2, p)  # Using Fermat's little theorem for modular inverse
    
    # Recover the session key
    session_key = (c2 * s_inv) % p
    
    return session_key

def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")

def sign_data(data, private_key, public_key):
    p, g, y = public_key
    
    # Calculate hash
    hash_value = int(hashlib.sha256(data.encode()).hexdigest(), 16) % (p-1)
    print(f"Hash (patient): {hash_value}")
    
    # Choose a random k that is coprime to p-1
    k = find_coprime(p-1)
    
    # Calculate r = g^k mod p
    r = pow(g, k, p)
    
    # Calculate s = k^-1 * (hash - x*r) mod (p-1)
    k_inv = pow(k, -1, p-1)  # Using Python 3.8+ m  odular inverse calculation
    s = (k_inv * (hash_value - private_key * r) % (p-1)) % (p-1)
    
    return (r, s)

def find_coprime(n):
    while True:
        k = random.randint(2, n-1)  
        if gcd(k, n) == 1:
            return k

def verification(dataToVerify, public_key, sgndata):
    p, g, y = public_key
    sig_r, sig_s = sgndata
    
    # Check if r is in the valid range
    if not (1 <= sig_r < p):
        return False
    
    # Check if s is in the valid range
    if not (1 <= sig_s < p-1):
        return False
    
    # Calculate hash value
    hash_value = int(hashlib.sha256(dataToVerify.encode()).hexdigest(), 16) % (p-1)
    
    # Calculate left side: g^hash mod p
    left_side = pow(g, hash_value, p)
    
    # Calculate right side: (y^r * r^s) mod p
    right_side = (pow(y, sig_r, p) * pow(sig_r, sig_s, p)) % p
    
    print(f"Hash: {hash_value}, g^hash mod p: {left_side}, y^r * r^s mod p: {right_side}")
    print(f"p: {p}, g: {g}, y: {y}, r: {sig_r}, s: {sig_s}")
    
    return left_side == right_side


def handle_patient(patient_socket, addr, doctor_public_key, doctor_private_key, doctor_id):
    try:
        print(f"[{get_timestamp()}] Connected to patient at {addr}")
        
        # Send doctor's public key to patient
        p_doctor, g_doctor, y_doctor = doctor_public_key
        patient_socket.send(f"{p_doctor},{g_doctor},{y_doctor}".encode())
        print(f"[{get_timestamp()}] Sent doctor's public key to patient")
        print(f"[{get_timestamp()}] Doctor's public key: p={p_doctor}, g={g_doctor}, y={y_doctor}")
        print("Doctor's p, g, y to the patient, this public key of doctors will be used by the patient for authentication request sending in phase 2")
        
        # Receive patient's public key
        patient_data = patient_socket.recv(4096).decode()
        p_patient, g_patient, y_patient, patient_id = map(int, patient_data.split(","))
        patient_public_key = (p_patient, g_patient, y_patient)
        print(f"[{get_timestamp()}] Received Patient's Public Key: p={p_patient}, g={g_patient}, y={y_patient}")
         

        
        #Phase 2 doctor, here we go


        auth_req = patient_socket.recv(4096).decode()
        auth_split = auth_req.split(',')
        opcode = auth_split[0]

        if(opcode == "10"):
            TS_i = int(auth_split[1])
            RN_i = int(auth_split[2])
            ID_GWN = auth_split[3]
            enc_key_c1 = int(auth_split[4])
            enc_key_c2 = int(auth_split[5])
            sig_r = int(auth_split[6])
            sig_s = int(auth_split[7])

            if(ID_GWN != doctor_id):
                print(f"Fake patient. Expected id: {doctor_id}, Got {ID_GWN}")
                #Have to do something about it (break connection with patient)
            
            current_time = int(time.time())
            if abs(current_time - TS_i) > 5:  # 30 seconds tolerance
                print(f"[{get_timestamp()}] Timestamp verification failed")
                patient_socket.send("FAILED".encode())
                return
            signature = (sig_r, sig_s)
            data_to_verify = f"{TS_i},{RN_i},{ID_GWN},{enc_key_c1},{enc_key_c2}"

            if verification(data_to_verify, patient_public_key, signature) == True:
                print("Good patient")
                print("OPCODE 10")
            else:
                print("Bad patient - Signature verification failed")
                #patient_socket.send("FAILED".encode())
                return
            
            encrypted_key = (enc_key_c1, enc_key_c2)
            K_Di_GWN = decrypt_session_key(encrypted_key, doctor_private_key, p_doctor)
            print(f"[{get_timestamp()}] Decrypted session key from patient: {K_Di_GWN}")

            TS_GWN = int(time.time())
            RN_GWN = random.randint(1, 2**64)
            id = auth_split[3]  # This should match what the patient is using 

            re_encrypted_key = encrypt_session_key(K_Di_GWN, patient_public_key)

            data_to_sign = f"{TS_GWN},{RN_GWN},{id},{re_encrypted_key[0]},{re_encrypted_key[1]}"
            doctor_signature = sign_data(data_to_sign, doctor_private_key, doctor_public_key)
            
            response = f"10,{TS_GWN},{RN_GWN},{id},{re_encrypted_key[0]},{re_encrypted_key[1]},{doctor_signature[0]},{doctor_signature[1]}"
            patient_socket.send(response.encode())
            print(f"[{get_timestamp()}] Sent authentication response to patient")


            verification_msg = patient_socket.recv(4096).decode()
            verification_parts = verification_msg.split(',')

            if verification_parts[0] == "20":
                session_key_recv = int(verification_parts[1])
                tsi_new = int(verification_parts[2])

                current_time = int(time.time())
                if abs(current_time - tsi_new) > 5:  # 5 seconds tolerance
                    print(f"[{get_timestamp()}] Timestamp verification failed for session key verification")
                    #patient_socket.send("FAILED".encode())
                    return

                session_key_unhashed = int(hashlib.sha256(f"{K_Di_GWN},{TS_i},{TS_GWN},{RN_i},{RN_GWN},{patient_id},{doctor_id}".encode()).hexdigest(), 16)
                session_key_hashed = int(hashlib.sha256(f"{session_key_unhashed},{tsi_new}".encode()).hexdigest(), 16)  

                if session_key_hashed == session_key_recv:
                    print("Session key verification done")
                    #This is utterly pointless
                    print("OPCODE: 20")  
                else:
                    print("Bad Patient -- session key not matched")
            else:
                print("Invalid Opcode. Expected: 20. Got Opcode")
        else:
            print("Invalid Opcode. Expected: 10 ")
    except Exception as e:
        print(f"[{get_timestamp()}] Error: {e}")
    
    finally:
        patient_socket.close()
        print(f"[{get_timestamp()}] Connection with patient {addr} closed")

def start_doctor_server(doctor_id):
    # Generate Doctor's ElGamal key pair (to be used for authentication in phase 2)
    doctor_public_key, doctor_private_key = generate_elgamal_keys()
    p, g, y = doctor_public_key
    print(f"[{get_timestamp()}] Doctor's Public Key: p={p}, g={g}, y={y}")
    print(f"[{get_timestamp()}] Doctor's Private Key: x={doctor_private_key}")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[{get_timestamp()}] Doctor server started at {HOST}:{PORT}")

    try:
        while True:
            patient_socket, addr = server_socket.accept()
            threading.Thread(
                target=handle_patient, 
                args=(patient_socket, addr, doctor_public_key, doctor_private_key, doctor_id)
            ).start()
    except KeyboardInterrupt:
        print(f"[{get_timestamp()}] Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Telemedical Doctor Server')
    parser.add_argument('--id', type=str, default="1", help='Doctor ID (default: 1)')
    
    args = parser.parse_args()
    doctor_id = args.id

    start_doctor_server(doctor_id)