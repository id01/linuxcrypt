## Linuxcrypt
Ransomware for Linux that uses SECP256K1 and AES256.  
I created this to show that Linux can have viruses...  
**I do not take responsibility for data loss or anything else caused by this program.**  
**This is for solely educational and demonstrative purposes only.**  
**Do not use this for any illegal activity.**  
Note: That XMR address in linuxcrypt is a dummy address. Nobody has the private key. Don't send anything to it.  
Runs on Python 2.7.  

## Usage
Generate a private key and put the private key in generate_key.py and the public key in linuxcrypt.py.  
Replace evil_address with some other text.  
Run `python linuxcrypt.py` on the victim machine to encrypt.  
Run `python generate_key.py` on the host machine to generate a decryption key.  
Run `python linuxdecrypt.py` on the victim machine, inputting the generated key, to decrypt.  