# client.py (FIXED)
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
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(message: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(message.encode('utf-8'))

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode('utf-8')

def receive_messages(sock, message_queue):
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
                    message = message_bytes.decode('latin-1')

                parts = message.split()
                if len(parts) == 3 and parts[1] == 'salt' and parts[0].startswith('@'):
                    sender_username = parts[0][1:]
                    received_salt = base64.b64decode(parts[2])
                    if sender_username != username:
                        message_queue.put(f"Enter encryption password for {sender_username}: ")
                        message_queue.put((sender_username, received_salt))  # Put salt in queue
                    continue

                if encryption_enabled:
                    try:
                        parts = message.split("] ", 1)
                        if len(parts) > 1:
                            prefix = parts[0] + "] "
                            encrypted_part = parts[1].strip()
                            decrypted_msg = decrypt_message(encrypted_part.encode('latin-1'), encryption_key)  # Corrected line
                            message_queue.put(prefix + decrypted_msg)
                        else:
                            # Handle cases where there's no prefix (unlikely, but good practice)
                            try:
                                decrypted_msg = decrypt_message(message.encode('latin-1'), encryption_key)
                                message_queue.put(decrypted_msg)
                            except:
                                message_queue.put(message) # not encrypted

                    except Exception as e:
                        message_queue.put(f"Decryption Error: {e}, Raw message: {message}")
                else:
                    message_queue.put(message)

        except Exception as e:
            message_queue.put(f"\nConnection lost or error: {e}")
            break

    sock.close()
    sys.exit(0)

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

    try:
        while True:
            try:
                message = message_queue.get(block=False)
                if isinstance(message, tuple):
                    sender_username, received_salt = message
                    password = input()
                    encryption_key = generate_key(password, received_salt)
                    # Notify server about the key
                    sock.sendall(f"set encryption {sender_username} {encryption_key.decode('latin-1')}\n".encode('utf-8'))
                    encryption_enabled = True
                    print(f"Encryption is enabled with a shared key from {sender_username}.\n")
                else:
                    print(message, end="")
            except queue.Empty:
                pass

            if msvcrt.kbhit():
                user_input = msvcrt.getch().decode('utf-8', errors='ignore')

                if user_input == '\b':
                    print('\b \b', end='', flush=True)
                    if 'current_input' in locals() and len(current_input) > 0:
                        current_input = current_input[:-1]
                elif user_input == '\r':
                    if 'current_input' in locals():
                        user_input = current_input + '\n'
                        print('\n', end='', flush=True)

                        if not user_input.strip():
                            current_input = ""
                            continue

                        if username is None:
                            username = user_input.strip()
                            sock.sendall(f"{username}\n".encode('utf-8')) # send username
                            current_input = "" # reset
                            continue

                        if user_input.strip().lower() == '@encrypt on':
                            password = input("Enter encryption password: ")
                            salt = os.urandom(16)
                            encryption_key = generate_key(password, salt)
                            sock.sendall(f"@salt {base64.b64encode(salt).decode('utf-8')}\n".encode('utf-8'))
                            print("Encryption enabled request sent.\n")
                            current_input = ""
                            continue

                        elif user_input.strip().lower() == '@encrypt off':
                            encryption_enabled = False
                            encryption_key = None
                            print("Encryption disabled.\n")
                            current_input = ""
                            continue

                        if encryption_enabled:
                            if user_input.startswith('@') and not user_input.startswith('@group'):
                                tokens = user_input.split()
                                recipient = tokens[0][1:]
                                message = ' '.join(tokens[1:])
                                encrypted_msg = encrypt_message(message, encryption_key)
                                sock.sendall(f"@{recipient} ".encode('utf-8') + encrypted_msg) # as bytes

                            elif user_input.startswith('@group send'):
                                tokens = user_input.split()
                                groupname = tokens[2]
                                message = ' '.join(tokens[3:])
                                encrypted_msg = encrypt_message(message, encryption_key)
                                sock.sendall(f"@group send {groupname} ".encode('utf-8') + encrypted_msg) # as bytes
                            else:
                                encrypted_msg = encrypt_message(user_input, encryption_key)
                                sock.sendall(encrypted_msg)
                        else:
                            sock.sendall(user_input.encode('utf-8'))

                        if user_input.strip() == '@quit':
                            print("You have quit the chat.\n")
                            break

                        current_input = ""

                elif user_input:
                    if 'current_input' not in locals():
                        current_input = ""
                    current_input += user_input
                    print(user_input, end='', flush=True)

    except KeyboardInterrupt:
        print("Closing client...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()