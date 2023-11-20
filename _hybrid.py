import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

TEST = True

def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    # passphrase = input('Enter a passphrase to protect the saved private key: ')
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

def load_keypair(privkeyfile):
    #passphrase = input('Enter a passphrase to decode the saved private key: ')
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def newline(s):
    return s + b'\n'

def test_random(nbytes):
    return b'\x00'*nbytes

# ----------------------------------
# processing command line parameters
# ----------------------------------

operation = 'dec'
pubkeyfile = 'test_pubkey.pem'
privkeyfile = 'test_keypair.pem'
inputfile = 'test_ciphertext4.txt'
outputfile = 'kimenet'
sign = False

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hkedp:s:i:o:')
except getopt.GetoptError:
    print('Usage:')
    print('  - RSA key pair generation:')
    print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
    print('  - encryption with optional signature generation:')
    print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
    print('  - decryption with optional signature verification:')
    print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h':
        print('Usage:')
        print('  - RSA key pair generation:')
        print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
        print('  - encryption with optional signature generation:')
        print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
        print('  - decryption with optional signature verification:')
        print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
        sys.exit(0)
    elif opt == '-k':
        operation = 'kpg'
    elif opt == '-e':
        operation = 'enc'    
    elif opt == '-d':
        operation = 'dec'    
    elif opt == '-p':
        pubkeyfile = arg
    elif opt == '-s':
        privkeyfile = arg
    elif opt == '-i':
        inputfile = arg
    elif opt == '-o':
        outputfile = arg

if (operation != 'enc') and (operation != 'dec') and (operation != 'kpg'):
    print('Error: Operation must be -k (for key pair generation) or -e (for encryption) or -d (for decryption).')
    sys.exit(1)
    
if (not pubkeyfile) and (operation == 'enc' or operation == 'kpg'):
    print('Error: Name of the public key file is missing.')
    sys.exit(1)

if (not privkeyfile) and (operation == 'dec' or operation == 'kpg'):
    print('Error: Name of the private key file is missing.')
    sys.exit(1)

if (not inputfile) and (operation == 'enc' or operation == 'dec'):
    print('Error: Name of input file is missing.')
    sys.exit(1)

if (not outputfile) and (operation == 'enc' or operation == 'dec'):
    print('Error: Name of output file is missing.')
    sys.exit(1)

if (operation == 'enc') and privkeyfile: 
    sign = True

# -------------------
# key pair generation
# -------------------

if operation == 'kpg': 
    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.publickey(), pubkeyfile)
    save_keypair(keypair, privkeyfile)
    print('Done.')

# ----------
# encryption
# ----------

elif operation == 'enc': 
    print('Encrypting...')

    # load the public key from the public key file and 
    # create an RSA cipher object
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)
    if TEST: 
        RSAcipher = PKCS1_OAEP.new(pubkey, randfunc=test_random)

    # read the plaintext from the input file
    with open(inputfile, 'rb') as f: 
        plaintext = f.read()

    # apply PKCS7 padding on the plaintext
    # TODO: padded_plaintext = ...
    padded_plaintext = Padding.pad(plaintext, AES.block_size)

    # generate a random symmetric key and a random IV
    # and create an AES cipher object
    # TODO: symkey = ... # we use a 256 bit (32 byte) AES key
    symkey = Random.get_random_bytes(32)  # 256-bit key

    if TEST: 
        symkey = b'testtesttesttesttesttesttesttest'
    # TODO: iv = ...
    # TODO: AEScipher = ...
    iv = Random.get_random_bytes(AES.block_size)  # 128-bit IV
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv)
    # encrypt the padded plaintext with the AES cipher
    # TODO: ciphertext = ...
    ciphertext = AEScipher.encrypt(padded_plaintext)

    #encrypt the AES key with the RSA cipher
    # TODO: encsymkey = ...
    encsymkey = RSAcipher.encrypt(symkey)

    # compute signature if needed
    if sign:
        keypair = load_keypair(privkeyfile)
        signer = PKCS1_PSS.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

    # write out the encrypted AES key, the IV, the ciphertext, and the signature
    with open(outputfile, 'wb') as f:
        f.write(newline(b'--- ENCRYPTED AES KEY ---'))
        f.write(newline(b64encode(encsymkey)))
        f.write(newline(b'--- IV FOR CBC MODE ---'))
        f.write(newline(b64encode(iv)))
        f.write(newline(b'--- CIPHERTEXT ---'))
        f.write(newline(b64encode(ciphertext)))
        if sign:
            f.write(newline(b'--- SIGNATURE ---'))
            f.write(newline(b64encode(signature)))

    print('Done.')
    if TEST: 
        print('Your solution to Challenge 3: ' + encsymkey[:16].hex())
        print('Hint: The correct solution starts with 822a19.')


# ----------
# decryption
# ----------

elif operation == 'dec':
    print('Decrypting...')

    # read and parse the input
    encsymkey = b''
    iv = b''
    ciphertext = b''

    with open(inputfile, 'rb') as f:        
        sep = f.readline()
        while sep:
            data = f.readline()
            data = data[:-1]   # removing \n from the end
            sep = sep[:-1]     # removing \n from the end

            if sep == b'--- ENCRYPTED AES KEY ---':
                encsymkey = b64decode(data)
            elif sep == b'--- IV FOR CBC MODE ---':
                iv = b64decode(data)
            elif sep == b'--- CIPHERTEXT ---':
                ciphertext = b64decode(data)
            elif sep == b'--- SIGNATURE ---':
                signature = b64decode(data)
                sign = True

            sep = f.readline()

    if (not encsymkey) or (not iv) or (not ciphertext):
        print('Error: Could not parse content of input file ' + inputfile)
        sys.exit(1)

    if sign and (not pubkeyfile):
        print('Error: Public key file is missing for  ' + inputfile)
        sys.exit(1)

    # verify signature if needed
    if sign:
        if not pubkeyfile:
            print('Error: Public key file is missing, signature cannot be verified.')
        else:
            pubkey = load_publickey(pubkeyfile)
            # TODO: verifier = ...
            verifier = PKCS1_PSS.new(pubkey)
            # TODO: hashfn = ...
            hashfn = SHA256.new()
            # TODO: hashfn.update(__)
            hashfn.update(encsymkey + iv + ciphertext)
            try:
                # TODO: verifier.verify(__, __)
                verifier.verify(hashfn, signature)
                print('Signature verification is successful.')
            except (ValueError, TypeError):
                print('Signature verification is failed.')
                yn = input('Do you want to continue (y/n)? ')
                if yn != 'y': 
                    sys.exit(1)

    # load the private key from the private key file and 
    # create the RSA cipher object
    keypair = load_keypair(privkeyfile)
    # TODO: RSAcipher = ...
    RSAcipher = PKCS1_OAEP.new(keypair)

    #decrypt the AES key and create the AES cipher object
    # TODO: symkey = ... 
    # TODO: AEScipher = ...
    symkey = RSAcipher.decrypt(encsymkey)
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv)

    # decrypt the ciphertext and remove padding
    # TODO: padded_plaintext = ...
    # TODO: plaintext = ...
    padded_plaintext = AEScipher.decrypt(ciphertext)
    plaintext = Padding.unpad(padded_plaintext, AES.block_size)
	
    # write out the plaintext into the output file
    with open(outputfile, 'wb') as f:
        f.write(plaintext)
	
    print('Done.')
    print('Your solution to Challenge 4: ' + plaintext[-16:].hex())
    print('Hint: The correct solution starts with 616e64.')
