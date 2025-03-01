import socket
import threading
import datetime
import random
import os
from cryptography.hazmat.primitives.asymmetric import dh

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
def encrypt_session_key(session_key, public_key):
    p, g, y = public_key
    
    # Convert session key to integer if it's bytes
    if isinstance(session_key, bytes):
        session_key = int.from_bytes(session_key, byteorder='big')
    
    # Choose a random ephemeral key k
    k = random.randint(2, p - 2)
    
    # Compute ciphertext
    c1 = pow(g, k, p)
    c2 = (session_key * pow(y, k, p)) % p
    
    return c1, c2

def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")

def handle_patient(patient_socket, addr, doctor_public_key, doctor_private_key):
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
        p_patient, g_patient, y_patient = map(int, patient_data.split(","))
        patient_public_key = (p_patient, g_patient, y_patient)
        print(f"[{get_timestamp()}] Received Patient's Public Key: p={p_patient}, g={g_patient}, y={y_patient}")
        
        # Generate a random session key (16 bytes = 128 bits)
        session_key = int.from_bytes(os.urandom(16), byteorder='big')
        print(f"[{get_timestamp()}] Generated session key: {session_key}")
        
        # Encrypt the session key using the patient's public key
        c1, c2 = encrypt_session_key(session_key, patient_public_key)
        print(f"[{get_timestamp()}] Encrypted session key: c1={c1}, c2={c2}")
        
        # Send the encrypted session key to the patient
        patient_socket.send(f"{c1},{c2}".encode())
        
        # Store the session key for this patient
        patient_id = f"{addr[0]}:{addr[1]}"
        patient_session_keys[patient_id] = session_key
        print(f"[{get_timestamp()}] Stored session key for patient {patient_id}")
        
        # Confirmation from patient
        confirmation = patient_socket.recv(4096).decode()
        print(f"[{get_timestamp()}] Patient confirmation: {confirmation}")

    except Exception as e:
        print(f"[{get_timestamp()}] Error: {e}")
    
    finally:
        patient_socket.close()
        print(f"[{get_timestamp()}] Connection with patient {addr} closed")

def start_doctor_server():
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
                args=(patient_socket, addr, doctor_public_key, doctor_private_key)
            ).start()
    except KeyboardInterrupt:
        print(f"[{get_timestamp()}] Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_doctor_server()