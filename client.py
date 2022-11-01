import binascii
import random
import time
import string
from socket import *
import crypto
from hashlib import sha256
import hmac, base64
import pyDes

used_cipher_suite = ""  # indicates the cipher suite
BigPrime = 1000000000000001953  # big prime for DH
base = 17   # base number for DH
client_random = 0   # client random number for DH
premaster_key = 0  # pre-master key
master_key = ""     # master key
session_key = ""    # session key
client_master_random = 0    # client random number for SHA256
received_server_master_random = 0   # server random number for SHA256
client_write_key = ""   # used for client DES to encrypt message
server_write_key = ""   # never used
client_write_MAC_key = ""   # used for generating mac
server_write_MAC_key = ""   # never used


def random_num(n) -> string:  # generate n-bits random string
    random_str = ''.join(random.sample(string.digits, n))
    return random_str


def read_public_key_from_crt(crt_file_name):    # draw public key from certificate
    with open(crt_file_name, 'rb') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        return crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())


def get_sha256(data, key) -> string:   # SHA256 encryption
    key = key.encode('utf-8')
    message = data.encode('utf-8')
    sign = base64.b64encode(hmac.new(key, message, digestmod=sha256).digest()).decode()
    return sign


def des_en(secret_key, text, cipher):   # DES encryption
    iv = secret_key
    if cipher == "DES":
        k = pyDes.des(secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    elif cipher == "DES3":
        k = pyDes.triple_des(secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    else:
        print("cipher wrong!")
        return "error"
    data = k.encrypt(text, padmode=pyDes.PAD_PKCS5)
    return binascii.b2a_hex(data).decode()


def des_de(secret_key, text, cipher):   # DES decryption
    iv = secret_key
    if cipher == "DES":
        k = pyDes.des(secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    elif cipher == "DES3":
        k = pyDes.triple_des(secret_key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    else:
        print("cipher wrong!")
        return "error"
    data = k.decrypt(binascii.a2b_hex(text), padmode=pyDes.PAD_PKCS5)
    return data.decode()


def ClientHello() -> None:
    print("******Starting client hello******")
    # exchange version
    client_version = "TLS 1.0.0"
    print("client version is " + client_version)
    clientSocket.send(client_version.encode('UTF-8'))
    time.sleep(1)
    # exchange cipher suite
    global cipher_suite, used_cipher_suite
    if cipher_suite == "DES":
        used_cipher_suite = "TLS_RSA_WITH_DES_SHA256"
    elif cipher_suite == "DES3":
        used_cipher_suite = "TLS_RSA_WITH_DES3_SHA256"
    print("client use " + used_cipher_suite + " as cipher suite")
    clientSocket.send(used_cipher_suite.encode('UTF-8'))
    time.sleep(1)
    # calculate first key
    global client_random
    global client_master_random
    client_random = random.randint(100, 999)
    client_first_key = (base ** client_random) % BigPrime
    # send big prime
    print("client send big prime: " + str(BigPrime))
    clientSocket.send(str(BigPrime).encode('UTF-8'))
    time.sleep(1)
    # send a big random to sever(used in later progress)
    client_master_random = random.randint(10000000000, 99999999999) ** 3
    print("client send master random: " + str(client_master_random))
    clientSocket.send(str(client_master_random).encode('UTF-8'))
    time.sleep(1)
    # send base number
    print("client send base number: " + str(base))
    clientSocket.send(str(base).encode('UTF-8'))
    time.sleep(1)
    # send client's first key
    print("client send first key: " + str(client_first_key) + "\n")
    clientSocket.send(str(client_first_key).encode('UTF-8'))
    time.sleep(1)


def ClientCert() -> None:
    print("******Client certificate action******")
    global received_server_master_random
    received_server_master_random = int(clientSocket.recvfrom(1024)[0].decode('UTF-8'))
    print("receive server's master random: " + str(received_server_master_random))
    received_server_first_key = int(clientSocket.recvfrom(1024)[0].decode('UTF-8'))
    print("server's first key is: " + str(received_server_first_key))
    global premaster_key
    premaster_key = (received_server_first_key ** client_random) % BigPrime
    print("shared key is: " + str(premaster_key))
    # received_server_cert = clientSocket.recvfrom(1024)[0].decode('UTF-8')
    received_server_cert = 'key/server/server.crt'
    print("receive server's certificate")
    received_server_cert_public_key_path = clientSocket.recvfrom(1024)[0].decode('UTF-8')
    server_cert_public_key = open(received_server_cert_public_key_path).read()
    print("receive server's certificate's public key")
    server_public_key = read_public_key_from_crt(received_server_cert)
    if server_public_key.decode() == server_cert_public_key:
        print("I trust this server")
    else:
        print("I don't trust this server")
        clientSocket.close()
    received_cert_request = clientSocket.recvfrom(1024)[0].decode('UTF-8')
    if received_cert_request == "please send me your certificate":
        client_cert_path = 'key/client/client.crt'
        client_cert_public_key_path = 'key/client/client_public.key'
        clientSocket.send(client_cert_path.encode('UTF-8'))
        time.sleep(1)
        clientSocket.send(client_cert_public_key_path.encode('UTF-8'))
        time.sleep(1)
        received_server_hello_done = clientSocket.recvfrom(1024)[0].decode('UTF-8')
        print(received_server_hello_done + "\n")
    else:
        print("no certificate request")
        clientSocket.close()


def GenerateMasterKey() -> None:
    print("******Generating master key******")
    global master_key
    print(str(premaster_key))
    print(str(client_master_random + received_server_master_random))
    master_key = get_sha256(str(premaster_key), str(client_master_random + received_server_master_random))
    print("master key is: " + master_key + "\n")


def GenerateSessionKey() -> None:
    global session_key
    session_key = get_sha256(master_key, str(client_master_random + received_server_master_random))
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


def SendMessages() -> None:
    print("******Generating session key******")
    GenerateSessionKey()
    print("******Sending messages******")
    global client_write_key, server_write_key, client_write_MAC_key, server_write_MAC_key
    global message
    message_mac = base64.b64encode(hmac.new(client_write_MAC_key.encode(), message.encode(), digestmod=sha256).digest())
    print("message mac is: " + message_mac.decode())
    des_key = client_write_key
    print("des key is: " + des_key)
    encrypted_message = des_en(des_key, message, cipher_suite)
    print("encrypted message is: " + encrypted_message)
    clientSocket.send(encrypted_message.encode())
    time.sleep(1)


message = input("please input your message: ")
cipher_suite = input("please choose a cypher suite from DES & DES3: ")
serverName = '127.0.0.1'
serverPort = 12345
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))
ClientHello()
ClientCert()
GenerateMasterKey()
SendMessages()

