import argparse, configparser, os, logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json, base64

FORMAT = 'utf-8'
HEADERSIZE = 10

key = get_random_bytes(16)
iv = get_random_bytes(16)
en_cipher = AES.new(key, AES.MODE_CBC)
messages = 'Hello, this is a test messagess.'

def buffer_msg(msg=''):
    """Encrypts a plain message with the session(AES) key and adds the encoded text's length at the beggining.\nReturns Bytes."""

    aes_enc_cipher = AES.new(key, AES.MODE_CBC)
    enc_msg = aes_enc_cipher.encrypt(pad(msg.encode(FORMAT), AES.block_size))
    iv = base64.b64encode(aes_enc_cipher.iv).decode(FORMAT)
    enc_msg_send = base64.b64encode(enc_msg).decode(FORMAT)
    message = json.dumps({'iv':iv, 'data': enc_msg_send})
    message_send = f'{str(len(message)):<{HEADERSIZE}}' + message
    return message_send.encode(FORMAT)

print(os.path.expanduser('~/Desktop/server_keys/'))


