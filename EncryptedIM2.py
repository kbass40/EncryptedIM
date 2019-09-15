import sys
import socket
import select
import argparse
import Crypto.Random
from Crypto.Cipher import AES
import hashlib
import hmac

HEADERSIZE = 256

portNumber = 9999
hostname = ""
confkey = ""
authkey = ""

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest = 'server', action = 'store_true')
    parser.add_argument('-c', dest = 'connect', metavar = 'HOSTNAME', type = str)
    parser.add_argument(dest = 'port', metavar = 'PORT', nargs = '?', type = int, default = portNumber)
    parser.add_argument('-confkey', dest = 'conf', type = str)
    parser.add_argument('-authkey', dest = 'auth', type = str)
    return parser.parse_args()

def init():
    args = parse_arguments()
    global portNumber
    global hostname
    global confkey
    global authkey
    if args.conf is None or args.auth is None:
        sys.exit()
    confkey = args.conf
    authkey = args.auth
    if args.connect is not None:     
        portNumber = args.port
        hostname = args.connect
        client()
    if args.server is not False:
        portNumber = args.port
        server()

def generate_iv():
    rnd = Crypto.Random.get_random_bytes(16)
    return rnd

def hash_key(key):
    hkey = hashlib.sha256(key)
    return hkey

def add_pad(msg):
    msg += b"\0" * (16 - (len(msg) % 16))
    return msg

def remove_pad(msg):
    return msg.rstrip(b"\0")

def encrypt_message(msg, key):
    iv = generate_iv()
    padded_message = add_pad(msg)
    hashed_key = hash_key(key).digest()
    encryptor = AES.new(hashed_key, AES.MODE_CBC, iv)
    return iv + encryptor.encrypt(padded_message)

def decrypt_message(encrypted_msg, key):
    iv = encrypted_msg[:16]
    hashed_key = hash_key(key).digest()
    decryptor = AES.new(hashed_key, AES.MODE_CBC, iv)
    padded_message = decryptor.decrypt(encrypted_msg[16:])
    plaintext_message = remove_pad(padded_message)
    return plaintext_message

def create_hmac(encrypted_message, key):
    auth_msg = hmac.new(key, encrypted_message, hashlib.sha256)
    return auth_msg.digest()

def server():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((socket.gethostname(), portNumber))
    # listen for incoming connections
    server_socket.listen()
    socket_list = [server_socket]
    try:
        client_socket, addr = server_socket.accept()
    except KeyboardInterrupt as error:
        sys.exit(0)

    while True:
        socket_list = [sys.stdin, client_socket]
        # wait for IO
        try:
            read, write, error = select.select(socket_list, [], [])
        except KeyboardInterrupt as error:
            sys.exit(0)
        for sock in read:
            # recieve message
            if sock == client_socket:
                # message = ""
                # newMessage = True
                while True:
                    msg = client_socket.recv(1024)
                    if msg is not None and msg != b'':
                        recv_hmac = msg[:32]
                        recv_encrypted_msg = msg[32:]
                        if recv_hmac == create_hmac(recv_encrypted_msg, authkey.encode()):
                            recv_decrypted_msg = decrypt_message(msg[32:], confkey.encode())
                            print(recv_decrypted_msg.decode())
                            break
                        else:
                            print("message has been tampered with")
                            sys.exit(0)
                    else:
                        sys.exit(0)
                    # # new message determine the length from the header
                    # if newMessage:
                    #     try:
                    #         length = int(msg[:HEADERSIZE])
                    #     except ValueError as error:
                    #         sys.exit(0)
                    #     newMessage = False
                    # # append message to needed for large messages
                    # message += msg.decode("utf-8")
                    # # print message once the entire message has been recieved
                    # if len(message) - HEADERSIZE == length:
                    #     print(message[HEADERSIZE:])
                    #     # reset values and break loop
                    #     newMessage = True
                    #     message = ""
                    #     break
            # send message
            else:
                # read from standard input
                try:
                    msg = input()
                except EOFError as error:
                    sys.exit(0)
                # encrypt message and generate auth msg
                encrypted_message = encrypt_message(msg.encode(), confkey.encode())
                hmac_message = create_hmac(encrypted_message, authkey.encode())
                secret_message = b"".join([hmac_message, encrypted_message])
                # # attach header to message
                # secret_message = f"{len(secret_message):<{HEADERSIZE}}" + secret_message
                # send message
                client_socket.send(secret_message)
    server_socket.close()

# client socket works in a very similar way to server socket with the exception of the initial connection
def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((hostname, portNumber))

    while True:
        socket_list = [sys.stdin, client_socket]
        try:
            read, write, error = select.select(socket_list, [], [])
        except KeyboardInterrupt as error:
            sys.exit(0)
        for sock in read:
            if sock == client_socket:
                # message = ""
                # newMessage = True
                while True:
                    msg = client_socket.recv(1024)
                    if msg is not None and msg != b'':
                        recv_hmac = msg[:32]
                        recv_encrypted_msg = msg[32:]
                        if recv_hmac == create_hmac(recv_encrypted_msg, authkey.encode()):
                            recv_decrypted_msg = decrypt_message(msg[32:], confkey.encode())
                            print(recv_decrypted_msg.decode())
                            break
                        else:
                            print("message has been tampered with")
                            sys.exit(0)
                    else:
                        sys.exit(0)
                    # if newMessage:
                    #     try:
                    #         length = int(msg[:HEADERSIZE])
                    #     except ValueError as error:
                    #         sys.exit(0)
                    #     newMessage = False
                    # message += msg.decode("utf-8")
                    # if len(message) - HEADERSIZE == length:
                    #     print(message[HEADERSIZE:])
                    #     newMessage = True
                    #     message = ""
                    #     break
            else:
                try:
                    msg = input()
                except EOFError as error:
                    sys.exit(0)
                # encrypt message and generate auth msg
                encrypted_message = encrypt_message(msg.encode(), confkey.encode())
                hmac_message = create_hmac(encrypted_message, authkey.encode())
                secret_message = b"".join([hmac_message, encrypted_message])
                # # attach header to message
                # secret_message = f"{len(secret_message):<{HEADERSIZE}}" + secret_message
                # send message
                client_socket.send(secret_message)
    client_socket.close()

def main():
    init()

if __name__ == "__main__":
    main()
