# StealthPyChat
AES/RSA-Encrypted Python 3.9 console chat.

This project's main objective for me was to learn the basics of the Public Key cryptography utilized in our day-to-life, primarily, by means of online chatting and web interactions as a whole.

The chat incorporates the following functions:

1) Diffie-Hellman key exchange combined with the hybrid AES/RSA encryption
2) Digital signatures
3) Multiple client connection handling (multitheading)
4) KeyWord server-to-client interaction
5) Chat logging into a file.

# Dependencies

## PyCryptodome
This library is used for RSA, AES encryption. Official API documentation: https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

All other libraries utilized in the project are python-built-in

# Demonstation
1) Starting the server with the following command: ```python3 server.py```
<img width="400" alt="Screenshot 2022-11-23 at 4 53 48 PM" src="https://user-images.githubusercontent.com/102734242/203565103-641941b7-946e-4ea5-ae63-0ebbdeada9d0.png">
2) After the server started listenning on certain IP adress and port, we can connect a client script running this command: ```python3 client.py -i 127.0.0.1 -p 5555 -k ~/Desktop/client_keys``` (the variables can change depending on your conf.ini values)
<img width="521" alt="Screenshot 2022-11-23 at 4 54 35 PM" src="https://user-images.githubusercontent.com/102734242/203566335-e64c03ec-c52c-433d-837e-57271c88ddb8.png">
<img width="520" alt="Screenshot 2022-11-23 at 4 55 07 PM" src="https://user-images.githubusercontent.com/102734242/203566572-75e4d478-9a67-4f68-a07d-08b6af750bcf.png">
3) Server output will look the following way after a client has successfully authorized:<img width="499" alt="Screenshot 2022-11-23 at 4 55 19 PM" src="https://user-images.githubusercontent.com/102734242/203566603-7cd04bc8-e772-4b3f-b131-84e8d3df85e3.png">

# Project flaws (still in development):
1) 10-number maximum message length—equivalent of the length of 1,000,000 characters—can be excessive, since any message will rarely reach a length of even 1000 characters
2) Key-Exchange algorithm may have some detrimental mistakes in its implementation in the code.
3) When exiting the scripts, their threads throw in errors.
