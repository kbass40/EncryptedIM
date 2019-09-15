import sys
import socket
import select
import argparse
import Crypto.Random
from Crypto.Cipher import AES
import hashlib 

HEADERSIZE = 256

portNumber = 9999
hostname = ""

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
    if args.connect is not None:     
        portNumber = args.port
        hostname = args.connect
        client()
    if args.server is not False:
        portNumber = args.port
        server()

def generage_iv():
    rnd = Crypto.Random.get_random_bytes(128)
    return rnd

def hash_key(key):
    hkey = hashlib.sha256(key.encode())
    print(hkey)
    print(hkey.digest())
    return hkey

def add_pad(msg):
    length = 16 - (len(msg) % 16)
    msg += bytes([length]) * 16
    return msg

def remove_pad(msg):
    msg = msg[:-msg[-1]]
    return msg

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
                message = ""
                newMessage = True
                while True:
                    msg = client_socket.recv(512)
                    # new message determine the length from the header
                    if newMessage:
                        try:
                            length = int(msg[:HEADERSIZE])
                        except ValueError as error:
                            sys.exit(0)
                        newMessage = False
                    # append message to needed for large messages
                    message += msg.decode("utf-8")
                    # print message once the entire message has been recieved
                    if len(message) - HEADERSIZE == length:
                        print(message[HEADERSIZE:])
                        # reset values and break loop
                        newMessage = True
                        message = ""
                        break
            # send message
            else:
                # read from standard input
                try:
                    msg = input()
                except EOFError as error:
                    sys.exit(0)
                # attach header to message
                msg = f"{len(msg):<{HEADERSIZE}}" + msg
                # send message
                client_socket.send(bytes(msg, "utf-8"))
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
                message = ""
                newMessage = True
                while True:
                    msg = client_socket.recv(512)
                    if newMessage:
                        try:
                            length = int(msg[:HEADERSIZE])
                        except ValueError as error:
                            sys.exit(0)
                        newMessage = False
                    message += msg.decode("utf-8")
                    if len(message) - HEADERSIZE == length:
                        print(message[HEADERSIZE:])
                        newMessage = True
                        message = ""
                        break
            else:
                try:
                    msg = input()
                except EOFError as error:
                    sys.exit(0)
                msg = f"{len(msg):<{HEADERSIZE}}" + msg
                client_socket.send(bytes(msg, "utf-8"))
    client_socket.close()

def main():
    IV = generage_iv()
    # key1 = hash_key("this is a key")
    # key2 = hash_key("fnlsdhfsldkfjlksdjflksenfilnsdlijflwiejfilwjefliwejfliwejlifjwelifjwelijffffffffffffffffffffffffffffffffffffffffljiljlijliwejililililililililililililililillifjwhliffsdfsjdfn")
    # print(key1.hexdigest())
    # print(key2.hexdigest())
    msg = add_pad("hello world".encode())
    print(msg)
    print(remove_pad(msg))
    init()

if __name__ == "__main__":
    main()