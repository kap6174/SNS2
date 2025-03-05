import socket
import random
import time 
import hashlib 
from cryptography.hazmat.primitives.asymmetric import dh
from math import gcd
import argparse

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000

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

# Decrypt session key using patient's private key
def decrypt_session_key(cipher_msg, key, p):
    c1, c2 = cipher_msg
    
    # Compute s = c1^x mod p
    s = pow(c1, key, p)
    
    # Compute s^(-1) mod p (modular inverse)
    s_inv = pow(s, p - 2, p)  # Using Fermat's little theorem for modular inverse
    
    # Recover the session key
    session_key = (c2 * s_inv) % p
    
    return session_key


def encrypt_session_key(msg, key):
    p, g, y = key
    
    # Convert message to integer if it's bytes
    if isinstance(msg, bytes):
        msg = int.from_bytes(msg, byteorder='big')
    
    # Choose a random ephemeral key k
    k = random.randint(2, p - 2)       
    
    # Compute ciphertext
    c1 = pow(g, k, p)
    c2 = (msg * pow(y, k, p)) % p
    
    return c1, c2


#WRTING CODE FOR PHASE 2

def generate_authMessage(patient_kr, doctor_ku, pid, did, patient_ku):
    K_di_gwn = random.randint(1, 2**128)
    E_ku_gwn = encrypt_session_key(K_di_gwn, doctor_ku)

    tsi = int(time.time())

    rni = random.randint(1, 2**64)

    data = f"{tsi},{rni},{did},{E_ku_gwn[0]},{E_ku_gwn[1]}"

    signdata = sign_data(data, patient_kr, patient_ku)

    auth_request = {
        "TS_i" : tsi,
        "RN_i" : rni,
        "ID_GWN" : did,
        "encrypted_key": E_ku_gwn,
        "signature" : signdata
    }

    return auth_request, K_di_gwn

def sign_data(data, private_key, public_key):
    p, g, y = public_key
    
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

def mod_inverse(k, p_minus_1):
    """Computes modular inverse using Extended Euclidean Algorithm"""
    return pow(k, p_minus_1 - 2, p_minus_1)  # Only works if p-1 is prime

def find_coprime(n):
    """Finds a random integer k that is coprime to n"""
    while True:
        k = random.randint(2, n-1)
        if gcd(k, n) == 1:
            return k

def verification(dataToVerify, public_key, sgndata):
    p, g, y = public_key
    sig_r, sig_s = sgndata
    
    if not (1 <= sig_r < p):
        return False
    
    if not (1 <= sig_s < p-1):
        return False

    hash_value = int(hashlib.sha256(dataToVerify.encode()).hexdigest(), 16) % (p-1)

    left_side = pow(g, hash_value, p)
    
    right_side = (pow(y, sig_r, p) * pow(sig_r, sig_s, p)) % p
    
    print(f"Hash: {hash_value}, g^hash mod p: {left_side}, y^r * r^s mod p: {right_side}")
    print(f"p: {p}, g: {g}, y: {y}, r: {sig_r}, s: {sig_s}")
    
    return left_side == right_side




    

def main(patient_id, doctor_id):
    try:
        patient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        patient_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[Patient] Connected to doctor server at {SERVER_HOST}:{SERVER_PORT}")
        
        # Receive doctor's public key
        doctor_data = patient_socket.recv(4096).decode()
        p_doctor, g_doctor, y_doctor = map(int, doctor_data.split(","))
        print(f"[Patient] Received Doctor's Public Key: p={p_doctor}, g={g_doctor}, y={y_doctor}")
        print("[Patient] This doctor's public key will be used for authentication requests in phase 2")

        # Generate Patient's ElGamal key pair
        patient_public_key, patient_private_key = generate_elgamal_keys()
        p, g, y = patient_public_key
        print(f"[Patient] Generated keys - Public Key: p={p}, g={g}, y={y}")
        print(f"[Patient] Private Key: x={patient_private_key}")

        # Send public key to doctor
        patient_socket.send(f"{p},{g},{y},{patient_id}".encode())
        print(f"[Patient] Sent public key to doctor")

        # Store doctor's public key for future use (phase 2)
        doctor_public_key = (p_doctor, g_doctor, y_doctor)



        auth_request, k_di_gwn = generate_authMessage(patient_private_key, doctor_public_key, patient_id, doctor_id, patient_public_key)

        auth_msg = f"10,{auth_request['TS_i']},{auth_request['RN_i']},{auth_request['ID_GWN']},{auth_request['encrypted_key'][0]},{auth_request['encrypted_key'][1]},{auth_request['signature'][0]},{auth_request['signature'][1]}"

        patient_socket.send(auth_msg.encode())
        print(f"Sent authetication code to doctor")

        #this is utterly pointless
        print("OPCODE: 10")

        #waitint for doctor's authetication code... (with blocking call)

        doctor_resp = patient_socket.recv(4096).decode()
        resp_split = doctor_resp.split(',')
        opcode = resp_split[0]

        
        if opcode == "10":

            tsg = int(resp_split[1])
            rng = int(resp_split[2])
            did = resp_split[3]
            enc_key_c1 = int(resp_split[4])
            enc_key_c2 = int(resp_split[5])
            sig_r = int(resp_split[6])
            sig_s = int(resp_split[7])

            curr_time = int(time.time())
            if abs(curr_time - tsg) > 5:
                print("Timestamp could not be verified: ")
                exit(1)
            
            sgndata2 = (sig_r, sig_s)
            dataInsideSig = f"{tsg},{rng},{did},{enc_key_c1},{enc_key_c2}"

            if verification(dataInsideSig, doctor_public_key, sgndata2) == True:
                print("Doctor's authentication code successful")
            else:
                print("Doctor's code could not be verified")
                exit(0)

            keyrecv = (enc_key_c1, enc_key_c2)
            k_di_gwn_recv = decrypt_session_key(keyrecv, patient_private_key, p)

            if(k_di_gwn_recv == k_di_gwn):
                print("I got the key I sent")
            else:
                print("Fake doctor")
                exit(0)

            session_key_unhashed = int(hashlib.sha256(f"{k_di_gwn},{auth_request['TS_i']},{tsg},{auth_request['RN_i']},{rng},{patient_id},{doctor_id}".encode()).hexdigest(), 16)
            tsi_new = int(time.time())

            session_key_hashed = int(hashlib.sha256(f"{session_key_unhashed},{tsi_new}".encode()).hexdigest(), 16)

            sk_to_send = f"20,{session_key_hashed},{tsi_new}"
            patient_socket.send(sk_to_send.encode())


            print(f"Sent session code to doctor")
            #this is utterly pointless 2
            print("OPCODE: 20")

            
        else:
            print("Different Opcode Received. Is that even possible?" + opcode)


    except Exception as e:
        print(f"[Patient] Error: {e}")
    
    finally:
        patient_socket.close()
        print(f"[Patient] Connection closed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Telemedical Patient Client')
    parser.add_argument('--patient-id', type=str, default="1", help='Patient ID (default: 1)')
    parser.add_argument('--doctor-id', type=str, default="1", help='Doctor ID to connect to (default: 1)')
    
    args = parser.parse_args()
    
    main(args.patient_id, args.doctor_id)