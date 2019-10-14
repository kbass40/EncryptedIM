#!/usr/bin/python

# UnencryptedIM provided by Professor Kevin Butler and written by Henry Tan
# I have added encryption to the unencrypted messeneger provided

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random
import Crypto.Random
import Crypto.Random.random
from Crypto.Cipher import AES
import hashlib
import hmac

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
g = 2
private = None
public = None
logger = logging.getLogger('main')
###########


def parse_arguments():
    parser = argparse.ArgumentParser(description = 'A P2P IM service.')
    parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
        help = 'Host to connect to')
    parser.add_argument('-s', dest='server', action='store_true',
        help = 'Run as server (on port 9999)')
    parser.add_argument(dest='port', metavar='PORT', nargs = '?', type=int, 
        default = DEFAULT_PORT,
        help = 'For testing purposes - allows use of different port')

    return parser.parse_args()

def print_how_to():
    print("This program must be run with exactly ONE of the following options")
    print("-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999")
    print("-s             : to run a server listening on tcp port 9999")

def sigint_handler(signal, frame):
    logger.debug("SIGINT Captured! Killing")
    global s, server_s
    if s is not None:
        s.shutdown(socket.SHUT_RDWR)
        s.close()
    if server_s is not None:
        s.close()

    quit()

def init():
    global s, private
    args = parse_arguments()

    private = generate_private_key()

    logging.basicConfig()
    logger.setLevel(logging.CRITICAL)
    
    #Catch the kill signal to close the socket gracefully
    signal.signal(signal.SIGINT, sigint_handler)

    if args.connect is None and args.server is False:
        print_how_to()
        quit()

    if args.connect is not None and args.server is not False:
        print_how_to()
        quit() 

    if args.connect is not None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
        # calculate shared key
        s.connect((args.connect, args.port))
        s.send(bytes(str(calculate_key_to_share()).encode()))
        key_recv = int(s.recv(2048).decode())
        public = calculate_public_key(key_recv)

    if args.server is not False:
        global server_s
        server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_s.bind(('', args.port))
        server_s.listen(1) #Only one connection at a time
        s, remote_addr = server_s.accept()
        # calculate shared key
        key_recv = int(s.recv(2048).decode())
        public = calculate_public_key(key_recv)
        s.send(bytes(str(calculate_key_to_share()).encode()))
        server_s.close()
        logger.debug("Connection received from " + str(remote_addr))

# generate private keys a & b 
# key between [1, p-2] 
def generate_private_key():
    global p
    rnd = Crypto.Random.random.randint(1, p - 2)
    return rnd

# calculate key to be shared
def calculate_key_to_share():
    global p, g, private
    return (pow(g, private, p))

# calculate shared public key
def calculate_public_key(recieved_key):
    global p, private
    return (pow(recieved_key, private, p))

# generate random initialization vector
def generate_iv():
    rnd = Crypto.Random.get_random_bytes(16)
    return rnd

# hash key to get uniform size
def hash_key(key):
    hkey = hashlib.sha256(key)
    return hkey

#pad your message so that is a variable length of 16 bytes
def add_pad(msg):
    msg += b"\0" * (16 - (len(msg) % 16))
    return msg

# remove the pad to read the message
def remove_pad(msg):
    return msg.rstrip(b"\0")

# AES encryption
def encrypt_message(msg, key):
    iv = generate_iv()
    padded_message = add_pad(msg)
    hashed_key = hash_key(key).digest()
    encryptor = AES.new(hashed_key, AES.MODE_CBC, iv)
    # concatanate your iv to encrypted message so that you can use the iv in decryption
    return iv + encryptor.encrypt(padded_message)

# AES decryption
def decrypt_message(encrypted_msg, key):
    iv = encrypted_msg[:16]
    hashed_key = hash_key(key).digest()
    decryptor = AES.new(hashed_key, AES.MODE_CBC, iv)
    padded_message = decryptor.decrypt(encrypted_msg[16:])
    plaintext_message = remove_pad(padded_message)
    return plaintext_message

def main():
  global s
  datalen=64
  
  init()

  inputs = [sys.stdin, s]
  outputs = [s]

  output_buffer = deque()

  while s is not None: 
    #Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else:
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable:
      data = s.recv(datalen)

      if ((data is not None) and (len(data) > 0)):
            recv_decrypted_msg = decrypt_message(data, str(public).encode())
            try:
                decoded_message = recv_decrypted_msg.decode()
            except UnicodeDecodeError as error:
                print("error in diffie hellman key agreement")
                quit()
            sys.stdout.write(decoded_message)
      else:
        #Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(1024)
      if(len(data) > 0):
        output_buffer.append(data)
      else:
        #EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()
        secret_message = encrypt_message(data.encode(), str(public).encode())
        bytesSent = s.send(secret_message)
        #If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

###########

if __name__ == "__main__":
    main()