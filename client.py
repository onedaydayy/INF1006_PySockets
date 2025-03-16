# client.py (Encryption/Decryption Restored)
import socket
import sys
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import queue
import msvcrt


def generate_key(password: str, salt: bytes) -> bytes:
    """Derives a secure key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
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

def receive_messages(sock, message_queue):
    """
    Continuously listen for server messages, decrypt if necessary, and print.
    """
    global encryption_enabled, encryption_key, username
    buffer = b""

    while True:
        try:
            data = sock.recv(1024)
            if not data:
                message_queue.put("Disconnected from server.\n")
                break

            buffer += data

            while True:
                newline_index = buffer.find(b'\n')
                if newline_index == -1:
                    break

                message_bytes = buffer[:newline_index + 1]
                buffer = buffer[newline_index + 1:]

                try:
                    message = message_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    message = message_bytes.decode('latin-1')  # Fallback

                parts = message.split()
                # --- Salt Handling (Receive) ---
                if len(parts) == 3 and parts[1].lower() == 'salt' and parts[0].startswith('@'):
                    sender_username = parts[0][1:]  # Remove @
                    received_salt = base64.b64decode(parts[2])
                     # Only prompt if it's NOT from ourselves
                    if sender_username != username:
                        message_queue.put(f"Enter encryption password for {sender_username}: ")
                        message_queue.put((sender_username, received_salt))  # Put in queue
                    continue  # Important: Skip further processing

                # --- Decryption Logic ---
                if encryption_enabled:
                    try:
                        parts = message.split("] ", 1)  # Split only once
                        if len(parts) > 1 and parts[0].startswith("[PM from"):
                            # PM decryption
                            encrypted_start = message_bytes.find(b"] ") + 2
                            encrypted_data = message_bytes[encrypted_start:].strip()
                            decrypted_msg = decrypt_message(encrypted_data, encryption_key)
                            message_queue.put(f"{parts[0]}] {decrypted_msg}")
                        elif len(parts) > 1 and parts[0].find(" -> ") > 0:
                            # Group message decryption
                            encrypted_start = message_bytes.find(b"] ") + 2
                            encrypted_data = message_bytes[encrypted_start:].strip()
                            decrypted_msg = decrypt_message(encrypted_data, encryption_key)
                            message_queue.put(f"{parts[0]}] {decrypted_msg}")
                        else: # normally
                            message_queue.put(message) # no decryption needed
                    except Exception as e:
                        message_queue.put(f"Decryption Error: {e}, Raw message: {message}")  # Show error
                else:
                    message_queue.put(message)


        except Exception as e:
            message_queue.put(f"\nConnection lost or error: {e}")
            break

    sock.close()
    sys.exit(0)  # Exit the entire process


# Global variables (Keep these)
encryption_enabled = False
encryption_key = None
username = None

def main():
    global encryption_enabled, encryption_key, username
    if len(sys.argv) < 3:
        print("Usage: python client.py <server_host> <port>")
        sys.exit(1)

    server_host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_host, port))
    except Exception as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    message_queue = queue.Queue()

    threading.Thread(target=receive_messages, args=(sock, message_queue), daemon=True).start()
    sock.sendall(b"CLIENT_READY\n")

    try:
        while True:
            # --- Handle messages from the queue (non-blocking) ---
            try:
                message = message_queue.get(block=False)
                if isinstance(message, tuple):  # It's a salt/password request
                    sender_username, received_salt = message
                    password = input() # prompt for password
                    encryption_key = generate_key(password, received_salt)
                    encryption_enabled = True
                    print(f"Encryption is enabled with a shared key from {sender_username}.\n")
                else:
                    print(message, end="") # just print
            except queue.Empty:
                pass

            # --- Handle user input (non-blocking) ---
            if msvcrt.kbhit():
                user_input = msvcrt.getch().decode('utf-8', errors='ignore')

                if user_input == '\b':  # Backspace
                    print('\b \b', end='', flush=True)
                    if 'current_input' in locals() and len(current_input) > 0:
                        current_input = current_input[:-1]

                elif user_input == '\r':  # Enter key
                    if 'current_input' in locals():
                        user_input = current_input + '\n' # combine
                        print('\n', end='', flush=True) # print to console

                        if not user_input.strip():  # Empty input
                            current_input = ""
                            continue

                        if username is None:
                            username = user_input.strip()

                        # --- Command Handling (Case-Insensitive) ---
                        if user_input.strip().lower() == '@encrypt on':
                            password = input("Enter encryption password: ")
                            salt = os.urandom(16)
                            encryption_key = generate_key(password, salt)
                            # --- Send salt (with username) ---
                            sock.sendall(f"@salt {base64.b64encode(salt).decode('utf-8')}\n".encode('utf-8'))
                            encryption_enabled = True
                            print("Encryption enabled.\n")
                            current_input = ""  # Reset
                            continue
                        elif user_input.strip().lower() == '@encrypt off':
                            encryption_enabled = False
                            encryption_key = None  # Clear the key
                            print("Encryption disabled.\n")
                            current_input = ""
                            continue
                        elif user_input.strip().lower() == '@history':
                            sock.sendall(b"@history\n")
                            current_input = ""
                            continue
                        elif user_input.strip().lower() == '@help':
                            sock.sendall(b"@help\n")
                            current_input = ""
                            continue

                        # --- Encryption/Sending ---
                        if encryption_enabled:
                            # Private message (encrypted)
                            if user_input.startswith('@') and not user_input.startswith('@group'):
                                tokens = user_input.split()
                                recipient = tokens[0][1:]
                                message = ' '.join(tokens[1:])
                                encrypted_msg = encrypt_message(message, encryption_key)
                                # Send recipient, then encrypted data
                                sock.sendall(f"@{recipient} ".encode('utf-8') + encrypted_msg)
                            # Group message (encrypted)
                            elif user_input.startswith('@group send'):
                                tokens = user_input.split()
                                groupname = tokens[2]
                                message = ' '.join(tokens[3:])
                                encrypted_msg = encrypt_message(message, encryption_key)
                                sock.sendall(f"@group send {groupname} ".encode('utf-8') + encrypted_msg)
                            else:
                                # Encrypt broadcast messages
                                encrypted_msg = encrypt_message(user_input, encryption_key)
                                sock.sendall(encrypted_msg)
                        else:
                            # Send unencrypted
                            sock.sendall(user_input.encode('utf-8'))

                        if user_input.strip() == '@quit':
                            print("You have quit the chat.\n")
                            break

                        current_input = ""  # Reset input

                elif user_input:  # Normal character input
                    if 'current_input' not in locals():
                        current_input = ""
                    current_input += user_input
                    print(user_input, end='', flush=True)  # Immediate display

    except KeyboardInterrupt:
        print("Closing client...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()