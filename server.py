import socket, sys, threading, datetime, os, logging, traceback

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

ADDRESS = ('127.0.0.1', 5555)
FORMAT = 'utf-8'
HEADERSIZE = 10
KEY_TAGS = {'auth_begin':'%AUTHINIT%', 'auth_accept':'%AUTHACCP%', 'disconnect':'%DISCONNT%'}
SPECIAL_SYMS = [",", ".", "/", "|", "{", "}", "'", "[", "]", "<", ">", "$", "%"]

## Start of the offline interraction
# Server generates its unique SPrivate => generates its unique SPub from the SPrivate
# Client generates its unique CPrivate

## 1) A client requests a server's public key => receives it
## 2) The client generates a new SESSION KEY (aka AES key) and encrypts it with the SPub using OAEP encryption
## !!! A new Session key is generated everytime on the client connecting to the server.
## 3) The server receives the client SESSION KEY, decrypts it with its private key, and stores the session key somewhere safe.
## 4) Now, both the client and the server have the AES encryption key and can safely send AES-encrypted messages to each other and decrypt them

# !!! Essentially, an SSL certificate is just a public key of a server.

# SECURITY FLAWS: 
# 1) Chat uses AES.MODE_ECB with no iv, meaning that all identical messages, will have the same encrypted version.
# 2) There is not a way to tell how big the encryted message is gonna be for a receipent - SOLVED: I can simply send the length of the encrypted message in plain, since, if an evesdropper is listenning, he will know the length of the ENCRYPTED MESSAGE anyway.

# For some reason, if name length is less than 9 (jakesssss), it gets padded in a weird (if 'jake', then it spaces up vastly to the right) - SOLVED: simply need to remove the padding calling the 'unpad' method from Crypto.Util.Padding.

class Server:

    def __init__(self):

        self.clients = {} # {clientsocket : (publicKey, sessionKey, nickname)}
        self.private_key = RSA.generate(2048)    
        with open('server_keys/server_private_key.pem', 'wb') as f:
            f.write(self.private_key.export_key())
        self.OAEP_cipher = PKCS1_OAEP.new(self.private_key)
        self.digital_signature = pkcs1_15.new(self.private_key)

        self.public_key = self.private_key.public_key()
        with open('server_keys/server_public_key.pem', 'wb') as f:
            f.write(self.public_key.export_key())

    def start(self):
        '''Creating a server socket, generating the private_key and public_key'''
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print('[*] Starting the server...')
        server_socket.bind(ADDRESS)

        server_socket.listen()
        print(f'[*] Server is listenning on {ADDRESS}')

        try:
            while True:
                client_socket, addr = server_socket.accept()

                print(f'[+] New connection from {addr}')

                self.recv_msg_thread = threading.Thread(target=self.recv_msg, args=(client_socket, addr))
                self.recv_msg_thread.start()
        except KeyboardInterrupt:
            print('[*] Shutting down the server...')
        
        sys.exit(0)

    def handshake(self, clientsocket, addr):
        try:
            clientsocket.send('%SPUBLKEY%'.encode(FORMAT))                              # Sends a keyword to the client, so the client knows what size to receive
            clientsocket.send(self.public_key.export_key('PEM'))                        # Sends the actual public key to the client
            client_pubkey = clientsocket.recv(2048)
            client_sessKey = self.OAEP_cipher.decrypt(clientsocket.recv(256))           # Decrypts the client-encoded sessionKey
            self.clients[clientsocket] = [client_pubkey, client_sessKey, None]          # Adds the session key in coherrance with the clientsocket

            AES_client = AES.new(client_sessKey, AES.MODE_ECB)                          # Secure communication is established at this point
            clientsocket.send(KEY_TAGS['auth_begin'].encode(FORMAT))
            while True:
                response = clientsocket.recv(10).decode(FORMAT)
                if response == KEY_TAGS['auth_begin']:
                    nickname_len = clientsocket.recv(HEADERSIZE).decode(FORMAT)
                    nickname_len = int(nickname_len)
                    # Receibe the encoded nickname => remove the added padding for the ECB mode => decoded it
                    nickname = unpad(AES_client.decrypt(clientsocket.recv(nickname_len)), AES.block_size).decode(FORMAT)
                    self.clients[clientsocket][2] = nickname.strip()
                    clientsocket.send(KEY_TAGS['auth_accept'].encode(FORMAT))
                    print(f'[+] Client {addr} is now <{nickname}>')
                    self.broadcast_msg(message=f"[{datetime.datetime.now().strftime('%Y-%M-%d %H:%M:%S')}] <{nickname}> has just connected!")
                    return True
                else:
                    print(f'[!] Client {addr} has failed to authenticate.')
                    clientsocket.close()
                    del self.clients[clientsocket]
                    return False

        except Exception as e:
            print(f'[!] Client {addr} has failed to connect. ({traceback.format_exc()})')
            clientsocket.close()
            del self.clients[clientsocket]

    def buffer_send_msg(self, clientsocket, msg=''):
        """Takes in plaintext, then converts it into the ciphertext, and returns the ciphertext's length + the ciphertext"""
        client_sessKey = self.clients[clientsocket][1]
        aes_cipher = AES.new(client_sessKey, mode=AES.MODE_ECB)
        enc_msg = aes_cipher.encrypt(pad(msg.encode(FORMAT), AES.block_size))
        message = f'{str(len(enc_msg)):<{HEADERSIZE}}'.encode(FORMAT) + enc_msg
        return message

    def recv_msg(self, clientsocket, addr):
        auth = self.handshake(clientsocket, addr)
        client_sessKey = self.clients[clientsocket][1]
        AES_client = AES.new(client_sessKey, AES.MODE_ECB)
        if auth == True:
            try:
                while True:
                    msg_len = clientsocket.recv(HEADERSIZE)
                    if msg_len:
                        timestamp = datetime.datetime.now().strftime('%Y-%M-%d %H:%M:%S')
                        msg_len = int(msg_len)
                        message = unpad(AES_client.decrypt(clientsocket.recv(msg_len)), AES.block_size).decode(FORMAT)
                        if message == '/q':
                            clientsocket.send(KEY_TAGS['disconnect'].encode(FORMAT))
                            print(f'[-] Client <{self.clients[clientsocket][2]}> has just disconnected.')
                            self.broadcast_msg(message=f'[-] Client <{self.clients[clientsocket][2]}> has just disconnected.')
                            break
                        message = (f'[{timestamp}] <{self.clients[clientsocket][2]}>: {message}')
                        print(message)
                        self.broadcast_msg(message=message, clientsocket=clientsocket)
                
                del self.clients[clientsocket]
                clientsocket.close()
            
            except KeyboardInterrupt:
                print('[*] Shutting down the server...')
            
            except ConnectionResetError:
                print(f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected (No client response received).')
                self.broadcast_msg(message=f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected (No client response received).')

            except Exception as e:
                print(f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected ({traceback.format_exc()}).')
                self.broadcast_msg(message=f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected ({traceback.format_exc()}).')
                del self.clients[clientsocket]
                clientsocket.close()

            sys.exit(0)
    
    def broadcast_msg(self, clientsocket=None, message=''):
        for client in list(self.clients.keys()):
            if client == clientsocket: # message from the server is not sent to the client which has sent this message
                continue
            try:
                message_send = self.buffer_send_msg(client, message)
                client.send(message_send)
            except BrokenPipeError:
                print()

if __name__ == '__main__':
    Server().start()