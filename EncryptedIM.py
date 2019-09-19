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
from Crypto.Cipher import AES
import hashlib
import hmac

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
confkey = ""
authkey = ""
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
    parser.add_argument('-confkey', dest = 'conf', type = str)
    parser.add_argument('-authkey', dest = 'auth', type = str)


    return parser.parse_args()

def print_how_to():
    print("This program must be run with exactly ONE of the following options")
    print("-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999")
    print("-s             : to run a server listening on tcp port 9999")
    print("-confkey       : key used for encryption")
    print("-authkey       : key used for hmac authentication")

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
    global s, authkey, confkey
    args = parse_arguments()

    logging.basicConfig()
    logger.setLevel(logging.CRITICAL)
    
    #Catch the kill signal to close the socket gracefully
    signal.signal(signal.SIGINT, sigint_handler)

    if args.conf is None:
        print_how_to()
        quit()
    
    if args.auth is None:
        print_how_to()
        quit()

    if args.connect is None and args.server is False:
        print_how_to()
        quit()

    if args.connect is not None and args.server is not False:
        print_how_to()
        quit() 

    confkey = args.conf
    authkey = args.auth

    if args.connect is not None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
        s.connect((args.connect, args.port))

    if args.server is not False:
        global server_s
        server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_s.bind(('', args.port))
        server_s.listen(1) #Only one connection at a time
        s, remote_addr = server_s.accept()
        server_s.close()
        logger.debug("Connection received from " + str(remote_addr))

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

# create hmac for authentication
def create_hmac(encrypted_message, key):
    auth_msg = hmac.new(key, encrypted_message, hashlib.sha256)
    return auth_msg.digest()

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
      #print "received packet, length "+str(len(data))

      if ((data is not None) and (len(data) > 0)):
            recv_hmac = data[:32]
            recv_encrypted_msg = data[32:]
            if recv_hmac == create_hmac(recv_encrypted_msg, authkey.encode()):
                recv_decrypted_msg = decrypt_message(data[32:], confkey.encode())
                try:
                    decoded_message = recv_decrypted_msg.decode()
                except UnicodeDecodeError as error:
                    print("conf keys do not match")
                    quit()
                sys.stdout.write(decoded_message)
            else:
                print("auth keys do not match or message has been tampered with")
                quit()
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
        encrypted_message = encrypt_message(data.encode(), confkey.encode())
        hmac_message = create_hmac(encrypted_message, authkey.encode())
        secret_message = b"".join([hmac_message, encrypted_message])
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