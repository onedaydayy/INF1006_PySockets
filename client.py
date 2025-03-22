import socket
import sys
import threading
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Encryption Utilities
class EncryptionUtils:
    @staticmethod
    def generate_key(password: str, salt: bytes) -> bytes:
        """Derives a secure key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_message(message: str, key: bytes) -> bytes:
        """Encrypts a message using Fernet (AES)."""
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted_message)

    @staticmethod
    def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
        """Decrypts a message using Fernet."""
        try:
            f = Fernet(key)
            decoded_message = base64.b64decode(encrypted_message)
            return f.decrypt(decoded_message).decode('utf-8')
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

class Client:
    def __init__(self, server_host, port):
        self.server_host = server_host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.encryption_enabled = False
        self.encryption_key = None
        self.encryption_password = None

    def connect(self):
        """Establish connection to the server and start message receiving thread."""
        try:
            self.sock.connect((self.server_host, self.port))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            print("Connected to server. Type your messages or commands below.")
        except Exception as e:
            print(f"Connection error: {e}")
            sys.exit(1)

    def receive_messages(self):
        """Continuously receive and process messages from the server."""
        while True:
            try:
                data = self.sock.recv(1024)
                if not data:
                    print("\nDisconnected from server")
                    break
                message = data.decode('utf-8')
                self.process_message(message)
            except Exception as e:
                print(f"\nConnection error: {e}")
                break
        self.sock.close()
        sys.exit(0)

    def process_message(self, message):
        """Process incoming messages and handle encryption if necessary."""
        try:
            if message.startswith('['):
                idx = message.find("] ")
                if idx != -1:
                    prefix = message[:idx+2]  # e.g., "[Alice] " or "[PM from Bob] "
                    content = message[idx+2:].strip()
                    
                    if content.startswith('ENC:'):
                        print(f"\n{prefix}[ENCRYPTED] Message received.")
                        if self.encryption_enabled and self.encryption_key:
                            try:
                                enc_data = base64.b64decode(content[4:])
                                decrypted = EncryptionUtils.decrypt_message(enc_data, self.encryption_key)
                                print(f"[Decrypted Message] {prefix}{decrypted}")
                            except Exception:
                                print("Failed to decrypt message with current key.")
                                self.prompt_for_decryption(prefix, content)
                        else:
                            self.prompt_for_decryption(prefix, content)
                    else:
                        print(message, end='')
                else:
                    print(message, end='')
            else:
                print(message, end='')
        except Exception as e:
            print(f"\nError processing message: {e}")

    def prompt_for_decryption(self, prefix, content):
        """Prompt user for password to decrypt a message."""
        while True:
            password = input("Enter password to decrypt (or type 'skip' to ignore): ")
            if password.lower() == "skip":
                print("Skipping decryption.")
                break

            try:
                enc_data = base64.b64decode(content[4:])
                salt = b'salt_'
                key = EncryptionUtils.generate_key(password, salt)
                decrypted = EncryptionUtils.decrypt_message(enc_data, key)
                print(f"[Decrypted Message] {prefix}{decrypted}")
                break
            except Exception:
                print("Wrong password. Try again.")

    def handle_encryption_command(self, tokens):
        """Handle encryption-related commands."""
        if len(tokens) >= 2:
            if tokens[1].lower() == 'on':
                print("Encryption mode ON")
                self.encryption_password = input("Enter encryption password: ")
                if self.encryption_password:
                    try:
                        salt = b'salt_'
                        self.encryption_key = EncryptionUtils.generate_key(self.encryption_password, salt)
                        self.encryption_enabled = True
                        # Send salt to server for other clients
                        self.sock.sendall(f"@salt {base64.b64encode(salt).decode('utf-8')}".encode('utf-8'))
                        print("Encryption enabled. All messages will be encrypted.")
                        
                        # Add prompt for first encrypted message
                        while True:
                            message = input("Enter your encrypted message (or type '@encrypt off' to disable encryption): ")
                            if message.lower() == '@encrypt off':
                                self.encryption_enabled = False
                                self.encryption_key = None
                                self.encryption_password = None
                                print("Encryption disabled. Messages will be sent in plaintext.")
                                break
                            elif message:
                                try:
                                    encrypted = EncryptionUtils.encrypt_message(message, self.encryption_key)
                                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                                    self.sock.sendall(formatted_msg.encode('utf-8'))
                                    print("[Encrypted] Message sent.")
                                    break
                                except Exception as e:
                                    print(f"Encryption failed: {e}")
                        return True
                    except Exception as e:
                        print(f"Failed to enable encryption: {e}")
                        self.encryption_enabled = False
                        self.encryption_key = None
                        self.encryption_password = None
                        return False
                else:
                    print("No password provided. Encryption not enabled.")
                    return False
            elif tokens[1].lower() == 'off':
                self.encryption_enabled = False
                self.encryption_key = None
                self.encryption_password = None
                print("Encryption disabled. Messages will be sent in plaintext.")
                return True
        return False

    def handle_salt_command(self, tokens):
        """Handle salt-related commands for encryption setup."""
        if len(tokens) >= 2:
            try:
                received_salt = base64.b64decode(tokens[1])
                password = input("Enter encryption password to join encrypted chat: ")
                self.encryption_key = EncryptionUtils.generate_key(password, received_salt)
                self.encryption_password = password
                self.encryption_enabled = True
                print("Encryption enabled with shared key.")
            except Exception as e:
                print(f"Failed to setup encryption: {e}")
            return True
        return False

    def handle_private_message(self, tokens):
        """Handle private messages with optional encryption."""
        try:
            parts = ' '.join(tokens).split(' ', 1)
            recipient = parts[0][1:]
            
            if len(parts) > 1 and self.encryption_enabled and self.encryption_key:
                message = parts[1]
                try:
                    encrypted = EncryptionUtils.encrypt_message(message, self.encryption_key)
                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                    self.sock.sendall(f"@{recipient} {formatted_msg}".encode('utf-8'))
                    print(f"Private message sent to {recipient}.")
                except Exception as e:
                    print(f"Encryption failed: {e}")
            else:
                self.sock.sendall(' '.join(tokens).encode('utf-8'))
                if len(parts) > 1:
                    print(f"Private message sent to {recipient}.")
        except Exception as e:
            print(f"Error sending private message: {e}")

    def handle_group_command(self, tokens):
        """Handle group-related commands with optional encryption."""
        try:
            if len(tokens) < 2:
                print("Invalid group command.")
                return
            
            if len(tokens) >= 4 and tokens[1].lower() == 'send' and self.encryption_enabled and self.encryption_key:
                groupname = tokens[2]
                message_body = ' '.join(tokens[3:])
                try:
                    encrypted = EncryptionUtils.encrypt_message(message_body, self.encryption_key)
                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                    self.sock.sendall(f"@group send {groupname} {formatted_msg}".encode('utf-8'))
                    print(f"Encrypted message sent to group {groupname}.")
                except Exception as e:
                    print(f"Encryption failed: {e}")
            else:
                self.sock.sendall(' '.join(tokens).encode('utf-8'))
        except Exception as e:
            print(f"Error handling group command: {e}")

    def handle_input(self, user_input):
        """Process user input and handle different types of commands."""
        try:
            tokens = user_input.split()
            if not tokens:
                return True

            command = tokens[0].lower()

            # Handle encryption commands
            if command == '@encrypt':
                if self.handle_encryption_command(tokens):
                    return True
                return True

            # Handle salt command
            if command.startswith('@salt'):
                if self.handle_salt_command(tokens):
                    return True
                return True

            # Handle standard commands
            if command in ['@names', '@history', '@help', '@quit']:
                self.sock.sendall(user_input.encode('utf-8'))
                if command == '@quit':
                    print("You have quit the chat.")
                    return False
                return True

            # Handle group commands
            if command.startswith('@group'):
                self.handle_group_command(tokens)
                return True

            # Handle private messages
            if command.startswith('@'):
                self.handle_private_message(tokens)
                return True

            # Handle regular messages with encryption if enabled
            if self.encryption_enabled and self.encryption_key:
                try:
                    encrypted = EncryptionUtils.encrypt_message(user_input, self.encryption_key)
                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                    self.sock.sendall(formatted_msg.encode('utf-8'))
                    print("Message sent (encrypted).")
                except Exception as e:
                    print(f"Encryption failed: {e}")
            else:
                self.sock.sendall(user_input.encode('utf-8'))
            return True
        except Exception as e:
            print(f"Error handling input: {e}")
            return True

    def run(self):
        """Main client loop for handling user input."""
        try:
            while True:
                user_input = input('')
                if not user_input:
                    continue
                if not self.handle_input(user_input):
                    break
        except KeyboardInterrupt:
            print("\nDisconnecting from server...")
        except Exception as e:
            print(f"\nError: {e}")
        finally:
            self.sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python client.py <server_host> <port>")
        sys.exit(1)
    client = Client(sys.argv[1], int(sys.argv[2]))
    client.connect()
    client.run()