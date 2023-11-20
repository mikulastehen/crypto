import sys, getopt
from Crypto import Random
from Crypto.Util import Padding
from Crypto.Cipher import AES
from Crypto.Protocol import KDF


TEST = True

operation = 'dec'
passphrase = 'ronrivest'
ifile_name = 'test_ciphertext2.crypted'
ofile_name = 'test1'

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hedp:i:o:')
except getopt.GetoptError:
    print('Usage: aes_cbc.py [-e|-d] -p <passphrase> -i <inputfile> -o <outputfile>')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h':
        print('Usage: aes_cbc.py [-e|-d] -p <passphrase> -i <inputfile> -o <outputfile>')
        sys.exit(0)
    elif opt == '-e':
        operation = 'enc'    
    elif opt == '-d':
        operation = 'dec'    
    elif opt == '-p':
        passphrase = arg
    elif opt == '-i':
        ifile_name = arg
    elif opt == '-o':
        ofile_name = arg

if (operation != 'enc') and (operation != 'dec'):
    print('Error: Operation must be -e (for encryption) or -d (for decryption).')
    sys.exit(1)
    
if not ifile_name:
    print('Error: Name of input file is missing.')
    sys.exit(1)

if not ofile_name:
    print('Error: Name of output file is missing.')
    sys.exit(1)

if  not passphrase:
    print('Error: No passphrase is given.')
    sys.exit(1)

if len(passphrase) < 8:
    print('Error: Passphrase is too short. Use at least 8 characters.')
    sys.exit(1)

# encryption
if operation == 'enc': 
    print('Encrypting...', end='')
	
    # read the content of the input file into a variable called plaintext
    with open(ifile_name, 'rb') as f:
        plaintext = f.read()

    # apply PKCS7 padding on the plaintext
    # TODO: padded_plaintext = Padding.pad(__, __, style=__)
    padded_plaintext = Padding.pad(plaintext, AES.block_size, style="pkcs7")



    # derive a 32-byte key from the passphrase using PBKDF2 
    # with a random salt and iteration count 1000
    salt = Random.get_random_bytes(AES.block_size)
    if TEST:
        salt = b'saltsaltsaltsalt'

    # TODO: key = KDF.PBKDF2(__, __, count=__, dkLen=__)
    key = KDF.PBKDF2(passphrase, salt, count=1000, dkLen=32)

    # generate random IV and create an AES-CBC cipher object
    # TODO: iv = Random.__(__)
    iv = Random.get_random_bytes(AES.block_size)

    if TEST: 
        iv = b'iviviviviviviviv'
    # TODO: cipher_CBC = AES.new(__, __, iv)
    cipher_CBC = AES.new(key, AES.MODE_CBC, iv)

    # also create an AES-ECB object for encrypting the IV
    cipher_ECB = AES.new(key, AES.MODE_ECB)

    # encrypt the IV in ECB mode and the padded plaintext in CBC mode
    # TODO: encrypted_iv = __.encrypt(__)
    # TODO: ciphertext = __.encrypt(__)
    encrypted_iv = cipher_ECB.encrypt(iv)
    ciphertext = cipher_CBC.encrypt(padded_plaintext)

    # write out the random salt used for key derivation, the encrypted IV,
    # and the encrypted plaintext to the output file
    with open(ofile_name, "wb") as f:
        f.write(salt)
        f.write(encrypted_iv)
        f.write(ciphertext)

    print('Done.')
    if TEST: 
        print('Your solution to Challenge 1: ' + ciphertext[-16:].hex())
        print('Hint: The correct solution starts with 157f06.')

# decryption
else:
    print('Decrypting...', end='')

    # read the salt, the encrypted IV, and the ciphertext from the input file
    with open(ifile_name, 'rb') as f:
        salt = f.read(AES.block_size)
        encrypted_iv = f.read(AES.block_size)
        ciphertext = f.read()
    
    # derive the 32-byte key from the passphrase using PBKDF2 
    # with the salt and iteration count 1000
    # TODO: key = ...
    key = KDF.PBKDF2(passphrase, salt, count=1000, dkLen=32)

    # create 2 AES cipher objects, one for decrypting the IV and one for decrypting the payload
    # and initialize these cipher objects with the appropriate parameters 
    # TODO: cipher_ECB = ...
    cipher_ECB = AES.new(key, AES.MODE_ECB)
    # TODO: iv = __.decrypt(__)
    iv = cipher_ECB.decrypt(encrypted_iv)
    # TODO: cipher_CBC = ...
    cipher_CBC = AES.new(key, AES.MODE_CBC, iv)

    # decrypt the ciphertext and remove padding
    # TODO: padded_plaintext = __.decrypt(__)
    padded_plaintext = cipher_CBC.decrypt(ciphertext)
    try:
        # TODO: plaintext = __.unpad(__, __, style=__)
        plaintext = Padding.unpad(padded_plaintext, AES.block_size, style="pkcs7")

        #pass # TODO: remove this line!
    except ValueError:
        print('Error: Incorrect padding detected, decryption failed.')
        sys.exit(1)

    # write out the plaintext into the output file
    with open(ofile_name, "wb") as f:
        f.write(plaintext)

    print('Done.')
    print('Your solution to Challenge 2: ' + plaintext[:16].hex())	
    print('Hint: The correct solution starts with 447571.')

