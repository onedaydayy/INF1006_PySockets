import socket
import sys
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

def generate_key(password: str, salt: bytes) -> bytes:
    """Derives a secure key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # Adjust for performance/security
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message: str, key: bytes) -> bytes:
    """Encrypts a message using Fernet (AES)."""
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode('utf-8'))
    return encrypted_message


def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    """Decrypts a message using Fernet."""
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

def receive_messages(sock):
    """
    Continuously listen for server messages, decrypt if necessary, and print.
    """
    global encryption_enabled, encryption_key  # Access global variables
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("Disconnected from server.")
                break

            message = data.decode('utf-8')
            # Check if message needs decryption
            if encryption_enabled:
                try:
                    # print("Trying to decrypt:", message)  # Debug print
                    # We expect the format:  [PM from sender] encrypted_message
                    parts = message.split("] ", 1) # split by ']'
                    if len(parts) > 1 and parts[0].startswith("[PM from"):
                        #print("Decrypting PM") #debug
                        decrypted_msg = decrypt_message(parts[1].encode('utf-8'), encryption_key)
                        print(f"{parts[0]}] {decrypted_msg}")

                    # Added: for group messages, check if it is encrypted and decrypt
                    elif len(parts) > 1 and parts[0].find(" -> ") > 0: # group message
                        decrypted_msg = decrypt_message(parts[1].encode('utf-8'), encryption_key)
                        print(f"{parts[0]}] {decrypted_msg}")

                    else:
                        print(message, end="") # not a pm, just print

                except Exception as e:
                    print(f"Decryption Error: {e}, Raw message: {message}")
                    #print(message, end='') # Fallback: Print raw if decryption fails
            else:
                print(message, end='')

        except Exception as e:
            print(f"\nConnection lost or error: {e}")
            break
    sock.close()
    sys.exit(0)


# Global variables for encryption state
encryption_enabled = False
encryption_key = None

def main():
    global encryption_enabled, encryption_key  # Access global variables
    # ... (rest of your client.py code, connection setup) ...
    if len(sys.argv) < 3:
        print("Usage: python client.py <server_host> <5000>")
        sys.exit(1)

    server_host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_host, port))
    except Exception as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    # Start a thread to continuously read messages from the server
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    # Now read input from the user and send to server
    try:
        while True:
            user_input = input('')
            if not user_input:
                continue

            # Handle encryption commands
            if user_input.strip().lower() == '@encrypt on':
                password = input("Enter encryption password: ")
                salt = os.urandom(16)  # Generate a random salt
                encryption_key = generate_key(password, salt)
                # Send salt to server, for other users
                sock.sendall(f"@salt {base64.b64encode(salt).decode('utf-8')}".encode('utf-8'))
                encryption_enabled = True
                print("Encryption enabled.")
                continue
            elif user_input.strip().lower() == '@encrypt off':
                encryption_enabled = False
                encryption_key = None
                print("Encryption disabled.")
                continue
            elif user_input.startswith('@salt'):
                # other user shared his/her salt
                received_salt = base64.b64decode(user_input.split()[1])
                password = input("Enter encryption password: ")
                encryption_key = generate_key(password, received_salt)
                encryption_enabled = True
                print("Encryption is enabled with a shared key.")
                continue

            # Encrypt message if enabled
            if encryption_enabled:
                # if private message
                if user_input.startswith('@') and not user_input.startswith('@group'):
                    tokens = user_input.split()
                    recipient = tokens[0][1:]
                    message = ' '.join(tokens[1:])
                    encrypted_msg = encrypt_message(message, encryption_key)
                    sock.sendall(f"@{recipient} {encrypted_msg.decode('latin-1')}".encode('utf-8')) # important decode
                # if group message
                elif user_input.startswith('@group send'):
                    tokens = user_input.split()
                    groupname = tokens[2]
                    message = ' '.join(tokens[3:])
                    encrypted_msg = encrypt_message(message, encryption_key)
                    sock.sendall(f"@group send {groupname} {encrypted_msg.decode('latin-1')}".encode('utf-8'))
                else:
                    # Broadcast. Encrypt the entire message
                    encrypted_msg = encrypt_message(user_input, encryption_key)
                    sock.sendall(encrypted_msg)  # Send bytes directly


            else:
                sock.sendall(user_input.encode('utf-8'))

            if user_input.strip() == '@quit':
                print("You have quit the chat.")
                break
    except KeyboardInterrupt:
        print("Closing client...")

    sock.close()

if __name__ == "__main__":
    main()
