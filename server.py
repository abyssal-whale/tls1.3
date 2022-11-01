import binascii
import random
import time
import pyDes
import string
from enum import Enum
from socket import *
import crypto
from hashlib import sha256
import hmac
import base64

cipher_suite = ""  # indicates the cipher suite
received_client_master_random = 0   # client random number for SHA256
server_master_random = 0    # server random number for DH
premaster_key = 0  # pre-master key
master_key = ""  # master key
session_key = ""    # session key
client_write_key = ""   # never used
server_write_key = ""   # used for server DES to decrypt message
client_write_MAC_key = ""   # never used
server_write_MAC_key = ""   # never used
lock = 0    # 类似于os中的conditional variable，防止并发
"""
class possible_cipher_suite(Enum):  # choose cipher_suite from this class
    one = "TLS_RSA_WITH_DES_SHA256"
    two = "TLS_RSA_WITH_DES3_SHA256"
    three = "RSA_WITH_AES_128_CBC_SHA256"
"""


def random_num(n) -> string:  # generate n-bits random string
    random_str = ''.join(random.sample(string.digits, n))
    return random_str


# draw public key from certificate
def read_public_key_from_crt(crt_file_name):
    with open(crt_file_name, 'rb') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        return crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())


def get_sha256(data, key) -> string:    # SHA256 encryption
    key = key.encode('utf-8')  # sha256加密的key
    message = data.encode('utf-8')  # 待sha256加密的内容
    sign = base64.b64encode(
        hmac.new(key, message, digestmod=sha256).digest()).decode()
    return sign


def des_en(secret_key, text, cipher):   # DES encryption
    iv = secret_key
    if cipher == "DES":
        k = pyDes.des(secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0",
                      pad=None, padmode=pyDes.PAD_PKCS5)
    elif cipher == "DES3":
        k = pyDes.triple_des(
            secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    else:
        print("cipher wrong!")
        return "error"
    data = k.encrypt(text, padmode=pyDes.PAD_PKCS5)
    return binascii.b2a_hex(data).decode()


def des_de(secret_key, text, cipher):   # DES decryption
    iv = secret_key
    if cipher == "DES":
        k = pyDes.des(secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0",
                      pad=None, padmode=pyDes.PAD_PKCS5)
    elif cipher == "DES3":
        k = pyDes.triple_des(
            secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    else:
        print("cipher wrong!")
        return "error"
    data = k.decrypt(binascii.a2b_hex(text), padmode=pyDes.PAD_PKCS5)
    return data.decode()


def ServerHello() -> None:
    print("******Starting server hello******")
    # receive client version
    received_client_version = connectionSocket.recv(1024).decode('UTF-8')
    print("receive client's version is " + received_client_version)
    # receive client's cipher suite
    received_cipher_suite = connectionSocket.recv(1024).decode('UTF-8')
    print("received cipher suite is: " + received_cipher_suite)
    time.sleep(1)
    # judge whether client's cipher suite is available
    print("cipher suite accepted")
    global cipher_suite
    if received_cipher_suite == "TLS_RSA_WITH_DES_SHA256":
        cipher_suite = "DES"
    elif received_cipher_suite == "TLS_RSA_WITH_DES3_SHA256":
        cipher_suite = "DES3"
    else:
        print("cipher wrong")
        serverSocket.close()
    # receive big prime
    big_prime = int(connectionSocket.recv(1024).decode('UTF-8'))
    print("received big prime is: " + str(big_prime))
    global received_client_master_random
    # receive client's master random(used in later progress)
    received_client_master_random = int(
        connectionSocket.recv(1024).decode('UTF-8'))
    print("received client's master random is: " +
            str(received_client_master_random))
    # receive base number
    base_num = int(connectionSocket.recv(1024).decode('UTF-8'))
    print("received base number is: " + str(base_num))
    # receive client's first key
    client_first_key = int(connectionSocket.recv(1024).decode('UTF-8'))
    print("received client's first key is: " + str(client_first_key))
    global server_master_random
    # generate server's random number for DH and send it
    server_master_random = random.randint(10000000000, 99999999999) ** 3
    print("server send master random: " + str(server_master_random))
    connectionSocket.send(str(server_master_random).encode('UTF-8'))
    time.sleep(1)
    server_random = random.randint(100, 999)
    # calculate pre-master key
    global premaster_key
    premaster_key = (client_first_key ** server_random) % big_prime
    server_first_key = (base_num ** server_random) % big_prime
    print("server send server's first key: " + str(server_first_key))
    connectionSocket.send(str(server_first_key).encode('UTF-8'))
    print("shared key is: " + str(premaster_key) + "\n")
    global lock
    lock=1
    time.sleep(1)


def ServerCert() -> None:  # send server's certificate
    print("******server send certificate******")
    # server_cert_path = 'key/server/server.crt'
    server_cert_public_key_path = 'key/server/server_public.key'
    print("server send certificate")
    # connectionSocket.send(server_cert_path.encode('UTF-8'))
    # time.sleep(1)
    print("server send certificate's public key")
    while lock==0:
        time.sleep(1)
    connectionSocket.send(server_cert_public_key_path.encode('UTF-8'))
    time.sleep(1)
    print("client certificate request")
    cer_req = "please send me your certificate"
    print('\n')
    connectionSocket.send(cer_req.encode('UTF-8'))


def ServerHelloDone() -> None:
    print("******Server hello done******")
    print("receive client's certificate")
    received_client_cert_path = connectionSocket.recv(1024).decode('UTF-8')
    print("receive client's certificate's public key")
    received_client_cert_public_key_path = connectionSocket.recv(
        1024).decode('UTF-8')
    client_cert_public_key = read_public_key_from_crt(
        received_client_cert_path)
    client_public_key = open(received_client_cert_public_key_path).read()
    if client_cert_public_key.decode() == client_public_key:
        print("I trust this client")
    else:
        print("I don't trust this client")
        serverSocket.close()
    connectionSocket.send("Server hello done".encode('UTF-8'))
    print("\n")


def GenerateMasterKey() -> None:
    print("******Generating master key******")
    global master_key
    master_key = get_sha256(str(premaster_key), str(
        received_client_master_random + server_master_random))
    print("master key is: " + master_key + "\n")


def GenerateSessionKey() -> None:
    global session_key
    session_key = get_sha256(master_key, str(
        received_client_master_random + server_master_random))
    print("session key is: " + session_key)
    global client_write_key, server_write_key, client_write_MAC_key, server_write_MAC_key
    if cipher_suite == "DES":
        client_write_key = session_key[:8]
        print("client_write_key:" + str(client_write_key))
        server_write_key = session_key[8:16]
        print("server_write_key:" + str(server_write_key))
        client_write_MAC_key = session_key[16:29]
        print("client_write_MAC_key" + str(client_write_MAC_key))
        server_write_MAC_key = session_key[29:]
        print("server_write_MAC_key" + str(server_write_MAC_key) + "\n")
    elif cipher_suite == "DES3":
        client_write_key = session_key[:16]
        print("client_write_key:" + str(client_write_key))
        server_write_key = session_key[16:32]
        print("server_write_key:" + str(server_write_key))
        client_write_MAC_key = session_key[32:38]
        print("client_write_MAC_key" + str(client_write_MAC_key))
        server_write_MAC_key = session_key[38:]
        print("server_write_MAC_key" + str(server_write_MAC_key) + "\n")


def ReceiveMessage() -> None:
    print("******Generating session key******")
    time.sleep(1)
    GenerateSessionKey()
    global client_write_key, server_write_key, client_write_MAC_key, server_write_MAC_key
    encrypted_message = connectionSocket.recv(1024)
    print("******Receiving messages******")
    print("received encrypted message is:" + encrypted_message.decode())
    des_key = client_write_key
    print("des key is: " + des_key)
    decrypted_message = des_de(des_key, encrypted_message, cipher_suite)
    print("client's plain message is: " + decrypted_message)


serverPort = 12345
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(10)
connectionSocket, addr = serverSocket.accept()
print("The server is ready to receive\n")
ServerHello()
ServerCert()
ServerHelloDone()
GenerateMasterKey()
ReceiveMessage()
