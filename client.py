import os, sys, datetime, socket, threading, traceback, argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ADDRESS = ('127.0.0.1', 5555)
HEADERSIZE = 10
FORMAT = 'utf-8'
KEY_TAGS = {'auth_begin':'%AUTHINIT%', 'auth_accept':'%AUTHACCP%', 'disconnect':'%DISCONNT%'}
SPECIAL_SYMS = [",", ".", "/", "|", "{", "}", "'", "[", "]", "<", ">", "$", "%"]

class Client:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.nickname = ''
        self.recv_msg_thread = threading.Thread(target=self.recv_msg,)
        self.send_msg_thread = threading.Thread(target=self.send_msg,)

        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key()

        self.session_key = get_random_bytes(16)
        self.aes_cipher = AES.new(self.session_key, AES.MODE_ECB)

    def main(self):
        try:
            print(f'Trying to connect to {ADDRESS}')
            self.client_socket.connect(ADDRESS)
            print(f'Successfully connected to {ADDRESS}')
            self.handshake()
        except Exception as e:
            print(f'Connection has failed ({e})...')
            self.client_socket.close()
    
    def buffer_msg(self, msg=''):
        """Encrypts a message with the session(AES) key and adds the encoded text's length at the beggining.\nReturns Bytes."""
        enc_msg = self.aes_cipher.encrypt(pad(msg, AES.block_size))
        enc_msg_len = str(len(enc_msg))
        message = f'{enc_msg_len:<{HEADERSIZE}}'.encode(FORMAT) + enc_msg
        return message

    def handshake(self):
        print('[*] Initiating the handshake..')
        try:
            while True:
                print('[*] Waiting for a server response..')

                response = self.client_socket.recv(HEADERSIZE).decode(FORMAT)
                if response == '%SPUBLKEY%':
                    print(f'[i] Server response: {response}')
                    server_pubkey = self.client_socket.recv(2048)
                    print('[i] Server pubKey has been received..')
                    self.OAEP_encr_server = PKCS1_OAEP.new(RSA.import_key(server_pubkey))
                    print('[i] Sending client PubKey..')
                    self.client_socket.send(self.public_key.export_key())
                    print('[i] Sending client SessionKey..')
                    self.client_socket.send(self.OAEP_encr_server.encrypt(self.session_key))
                    keys_sent = True
                if response == KEY_TAGS['auth_begin']:
                    while True:
                        self.nickname = input('[+] Enter your preffered name (20 characters or less): ').encode(FORMAT)
                        if len(self.nickname) <= 20 and any(x in SPECIAL_SYMS for x in [*self.nickname]) == False: ## '[*somevariable]' just converts the variable into a list of its symbols
                            self.client_socket.send(KEY_TAGS['auth_begin'].encode(FORMAT))
                            self.client_socket.send(self.buffer_msg(self.nickname))
                            break
                        else:
                            print('[!] The name should be 20 characters or less and shouldn not contain special characters')
                if response == KEY_TAGS['auth_accept']:
                    self.send_msg()
        except Exception as e:
            print(f'Connection has failed ({traceback.format_exc()})...')
            self.client_socket.close()

    def send_msg(self):
        self.recv_msg_thread.start()
        try:
            while True:
                message = input(f'').encode()
                message_send = self.buffer_msg(message)
                self.client_socket.send(message_send)
        except BrokenPipeError:
            sys.exit(0)

    def recv_msg(self):
        try:
            while True:
                msg_len = self.client_socket.recv(HEADERSIZE).decode(FORMAT)
                if msg_len:
                    if msg_len in KEY_TAGS.values():
                        if msg_len == KEY_TAGS['disconnect']:
                            break
                    msg_len = int(msg_len)
                    recved_msg = self.client_socket.recv(msg_len)
                    message = unpad(self.aes_cipher.decrypt(recved_msg), AES.block_size).decode(FORMAT)
                    print(f'{message}')
            print('[-] You have been disconnected')
        except ConnectionResetError:
            print('[!] The connection has been abrupted.')
        except BrokenPipeError:
            print('[!] The server is not reachable.')

if __name__ == '__main__':
    Client().main()
    argparse.Action()