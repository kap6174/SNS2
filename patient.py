import socket
import random
from cryptography.hazmat.primitives.asymmetric import dh

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
def decrypt_session_key(ciphertext, private_key, p):
    c1, c2 = ciphertext
    
    # Compute s = c1^x mod p
    s = pow(c1, private_key, p)
    
    # Compute s^(-1) mod p (modular inverse)
    s_inv = pow(s, p - 2, p)  # Using Fermat's little theorem for modular inverse
    
    # Recover the session key
    session_key = (c2 * s_inv) % p
    
    return session_key

def main():
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
        patient_socket.send(f"{p},{g},{y}".encode())
        print(f"[Patient] Sent public key to doctor")

        # Receive encrypted session key from doctor
        encrypted_key_data = patient_socket.recv(4096).decode()
        c1, c2 = map(int, encrypted_key_data.split(","))
        print(f"[Patient] Received encrypted session key: c1={c1}, c2={c2}")

        # Decrypt the session key
        session_key = decrypt_session_key((c1, c2), patient_private_key, p)
        print(f"[Patient] Decrypted session key: {session_key}")

        # Store doctor's public key for future use (phase 2)
        doctor_public_key = (p_doctor, g_doctor, y_doctor)
        print(f"[Patient] Stored doctor's public key for future authentication")

        # Send confirmation to doctor
        patient_socket.send("Session key received and decrypted successfully".encode())
        print(f"[Patient] Sent confirmation to doctor")

    except Exception as e:
        print(f"[Patient] Error: {e}")
    
    finally:
        patient_socket.close()
        print(f"[Patient] Connection closed")

if __name__ == "__main__":
    main()