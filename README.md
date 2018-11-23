# ransomware_script
Simple ransomware scripts developed in Python 3, using [cryptography.io](https://cryptography.io/en/latest/) library. Initial script (ransomware.py) was created for the final project of the course Network Awareness (Técnicas de Perceção de Redes).



The second script (ransom_hybrid.py) was an enchancement of the first one, providing stronger file encryption by using a hybrid cryptogtaphy strategy. 

This was done mostly for fun and interest on the topic of ransomware.

# ransomware.py
The script in, both encryption or decryption modes, will iterate through the selected directory (as input), parsing each file and encrypting/decrypting its contents using the simmetric key generated from the given user password.
A file is read in chunks of 65536 bytes and each is encrypted with the same key. When encrypting, the size of the original file is saved in the header of the encrypted file, along with the initialization vector (IV), which varies from file to file. This is done in order to ease the decrypting process. In the decryption stage, the filesize and iv are read, followed by the chunk read and decryption.

# ransom_hybrid.py
In this case a hybrid cryptography strategy was implemented. It works by creating a RSA Assymetric key pair at startup. When encrypting, the private key of the pair will be saved in the working directory as a encrypted PEM file, using the user given password. Then for each parsed file a 32 bytes random symmetric key will be generated along with the IV. The generated key is then encrypted using the private key and will be stored in the header metadata of the destination file, together with the original file size and the IV. In the reverse process the private key, stored in PEM format on the working directory, is loaded into memory. For each file the metadata information will be read, the simmetric key will be decrypted (using the private key), followed by the decryption of the original file content. 

This approach is slower compared to the first one, but offers way stronger security.

# Warning!
If your adventurous enough to try this beware since it can VERY easily lock your files, turning them useless. Make sure you don't mistype the folder path you're targeting
