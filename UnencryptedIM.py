import sys
import socket
import select

HEADERSIZE = 256

portNumber = 9999
serv = False

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
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((socket.gethostname(), portNumber))
    # listen for incoming connections
    server_socket.listen()
    socket_list = [server_socket]
    client_socket, addr = server_socket.accept()

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

if serv:
    server()
else:
    client()