import sys
import socket
import select

HEADERSIZE = 256

portNumber = 9999
serv = False
hostname = socket.gethostname()

def invalidArguments(message):
    print(message)
    sys.exit(0)

if len(sys.argv) < 2:
    invalidArguments("not enough arguments")
elif sys.argv[1] == "-s":
    serv = True
    if len(sys.argv) > 2:
        portNumber = int(sys.argv[2])
elif sys.argv[1] == "-c":
    serv = False
    hostname = sys.argv[2]
    if len(sys.argv) > 3:
        portNumber = int(sys.argv[3])
else:
    invalidArguments("invalid arguments")

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((hostname, portNumber))
    server_socket.listen()
    socket_list = [server_socket]
    client_socket, addr = server_socket.accept()

    while True:
        socket_list = [sys.stdin, client_socket]
        read, write, error = select.select(socket_list, [], [])
        for sock in read:
            if sock == client_socket:
                message = ""
                newMessage = True
                while True:
                    msg = client_socket.recv(512)
                    if newMessage:
                        length = int(msg[:HEADERSIZE])
                        newMessage = False
                    message += msg.decode("utf-8")
                    if len(message) - HEADERSIZE == length:
                        print(message[HEADERSIZE:])
                        newMessage = True
                        message = ""
                        break
            else:
                msg = input()
                msg = f"{len(msg):<{HEADERSIZE}}" + msg
                client_socket.send(bytes(msg, "utf-8"))
    server_socket.close()

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((hostname, portNumber))

    while True:
        socket_list = [sys.stdin, client_socket]
        read, write, error = select.select(socket_list, [], [])
        for sock in read:
            if sock == client_socket:
                message = ""
                newMessage = True
                while True:
                    msg = client_socket.recv(512)
                    if newMessage:
                        length = int(msg[:HEADERSIZE])
                        newMessage = False
                    message += msg.decode("utf-8")
                    if len(message) - HEADERSIZE == length:
                        print(message[HEADERSIZE:])
                        newMessage = True
                        message = ""
                        break
            else:
                msg = input()
                msg = f"{len(msg):<{HEADERSIZE}}" + msg
                client_socket.send(bytes(msg, "utf-8"))
    client_socket.close()

if serv:
    server()
else:
    client()