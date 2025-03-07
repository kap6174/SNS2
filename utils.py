import base64
import datetime
import socket
import random
import time 
import hashlib 
from cryptography.hazmat.primitives.asymmetric import dh
from math import gcd
import argparse
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def get_prime_and_generator():
    parameters = dh.generate_parameters(generator=2, key_size=512)
    p = parameters.parameter_numbers().p  
    g = find_generator(p)
    return p, g

def find_generator(p):
    for g in range(2, p - 1):
        if pow(g, (p - 1) // 2, p) != 1:  # Basic check for primitive root
            return g
    return 2  # Fallback

def mod_inverse(k, p_minus_1):
    return pow(k, p_minus_1 - 2, p_minus_1)  # Only works if p-1 is prime

def find_coprime(n):
    while True:
        k = random.randint(2, n-1)
        if gcd(k, n) == 1:
            return k
        
def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")

