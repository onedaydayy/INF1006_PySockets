import socket
import sys
import threading
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import struct
import hashlib
import os
import re

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
    # File transfer constants
    CHUNK_SIZE = 8192  # 8KB chunks for file transfer
    HEADER_FORMAT = "!Q"  # Format for file size (unsigned long long)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    def calculate_md5(self, filepath):
        """Calculate MD5 hash of a file"""
        md5_hash = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    
    def handle_file_transfer_command(self, tokens):
        """Handle file transfer commands"""
        if len(tokens) < 3:
            print("Usage: @sendfile <filename> <recipient> or @sendfile-group <filename> <group_name>")
            return
        
        filename = tokens[1]
        if not os.path.exists(filename):
            print(f"Error: File '{filename}' not found.")
            return
        
        # Show preview for text files
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                preview = f.read(1024)  # Read first 1KB
                print(f"\nPreview of {filename}:")
                print("=" * 30)
                print(preview)
                if len(preview) == 1024:
                    print("\n... (file continues)")
                print("=" * 30)
        except UnicodeDecodeError:
            print(f"Note: '{filename}' is a binary file and cannot be previewed.")
        except Exception as e:
            print(f"Note: Cannot preview file: {e}")
            
        # Send the command to server
        self.sock.sendall(' '.join(tokens).encode('utf-8'))
        print(f"File transfer request sent for '{filename}'")
        
        # Store the filename for later use
        self.pending_send_file = filename
    
    def send_file(self, filepath):
        """Send a file over the socket connection"""
        try:
            # Get file size
            filesize = os.path.getsize(filepath)
            
            # Send filesize header
            self.sock.sendall(struct.pack(self.HEADER_FORMAT, filesize))
            
            # Calculate and send MD5 hash
            md5_hash = self.calculate_md5(filepath)
            self.sock.sendall(md5_hash.encode())
            
            # Send file content
            sent_size = 0
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
                    sent_size += len(chunk)
                    # Print progress
                    progress = (sent_size / filesize) * 100
                    print(f"\rSending: {progress:.1f}%", end='', flush=True)
            print("\nFile sent successfully!")
            return True
        except Exception as e:
            print(f"\nError sending file: {e}")
            return False
    
    def receive_file(self, filename):
        """Receive a file over the socket connection"""
        try:
            # Create downloads directory if it doesn't exist
            os.makedirs('downloads', exist_ok=True)
            save_path = os.path.join('downloads', filename)
            
            # Receive filesize header
            header = self.sock.recv(self.HEADER_SIZE)
            filesize = struct.unpack(self.HEADER_FORMAT, header)[0]
            
            # Receive MD5 hash
            md5_hash = self.sock.recv(32).decode()  # MD5 hash is 32 characters
            
            # Receive and save file
            received_size = 0
            with open(save_path, "wb") as f:
                while received_size < filesize:
                    chunk_size = min(self.CHUNK_SIZE, filesize - received_size)
                    chunk = self.sock.recv(chunk_size)
                    if not chunk:
                        raise Exception("Connection closed before file transfer completed")
                    f.write(chunk)
                    received_size += len(chunk)
                    # Print progress
                    progress = (received_size / filesize) * 100
                    print(f"\rReceiving: {progress:.1f}%", end='', flush=True)
            
            # Verify MD5 hash
            received_md5 = self.calculate_md5(save_path)
            if received_md5 != md5_hash:
                os.remove(save_path)  # Delete corrupted file
                raise Exception("File transfer failed: MD5 verification failed")
            
            print(f"\nFile received successfully and saved as '{save_path}'")
            return True
        except Exception as e:
            print(f"\nError receiving file: {e}")
            return False
        
    def view_file_contents(self, filename):
        """View contents of a file"""
        try:
            # Check in current directory first
            if os.path.exists(filename):
                filepath = filename
            else:
                # Check in downloads directory
                downloads_path = os.path.join('downloads', filename)
                if os.path.exists(downloads_path):
                    filepath = downloads_path
                else:
                    print(f"Error: File '{filename}' not found in current directory or downloads folder.")
                    return False

            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size > 1024 * 1024:  # If file is larger than 1MB
                print(f"Warning: File '{filename}' is large ({file_size/1024/1024:.1f}MB). ")
                response = input("Do you want to continue? (y/n): ")
                if response.lower() != 'y':
                    return False

            try:
                # Try to read as text file
                with open(filepath, 'r', encoding='utf-8') as f:
                    print(f"\n=== Contents of {filename} ===")
                    print(f.read())
                    print("=" * 30)
                return True
            except UnicodeDecodeError:
                print(f"Error: '{filename}' appears to be a binary file and cannot be displayed as text.")
                return False

        except Exception as e:
            print(f"Error viewing file: {e}")
            return False
        
    def __init__(self, server_host, port):
        self.server_host = server_host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.encryption_enabled = False
        self.encryption_key = None
        self.encryption_password = None
        self.chat_history = []  # Add chat history list
        self.user_encryption_keys = {}  # Store encryption keys for different users
        self.group_encryption_keys = {}  # Store encryption keys for different groups
        self.username = None  # Store current user's username

    def connect(self):
        """Establish connection to the server and perform username negotiation."""
        try:
            self.sock.connect((self.server_host, self.port))

            while True:
                data = self.sock.recv(1024).decode('utf-8').strip()
                if "Enter a unique username" in data:
                    while True:
                        username = input("Enter a unique username: ").strip()
                        
                        if not re.match("^[A-Za-z0-9_]+$", username):
                            print("Invalid username. Use only letters, numbers, and underscores.")
                            continue  # Retry username input

                        self.sock.sendall(username.encode('utf-8'))

                        # Wait for server response about the username
                        server_response = self.sock.recv(1024).decode('utf-8').strip()
                        if "Username is already taken" in server_response:
                            print(server_response)
                            continue  # Retry username input
                        elif "Welcome to the chat" in server_response:
                            print(server_response)
                            threading.Thread(target=self.receive_messages, daemon=True).start()
                            print("You can now start typing your messages.")
                            return
                        else:
                            print(server_response)
                else:
                    print(data)

        except Exception as e:
            print(f"Connection error: {e}")
            sys.exit(1)

    def receive_messages(self):
        """Continuously receive and process messages from the server."""
        while True:
            try:
                data = self.sock.recv(1024)
                if not data:
                    print("\nServer closed connection.")
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
            # Handle file transfer start signal
            if message.strip() == "FILE_TRANSFER_START":
                if hasattr(self, 'pending_send_file'):
                    filename = self.pending_send_file
                    print(f"Starting file transfer for '{filename}'...")
                    self.send_file(filename)
                    delattr(self, 'pending_send_file')
                return
                
            # Handle regular messages
            if message.startswith('[FILE]'):
                print(message, end='')
                self.chat_history.append(message)  # Store file transfer message

            elif message.startswith('['):
                # Support formats like: [group][user] message
                prefix_end = message.find("] ")
                if prefix_end == -1:
                    # Might be [group][user] format
                    group_end = message.find("]")
                    user_start = message.find("[", group_end + 1)
                    user_end = message.find("]", user_start + 1)

                    if group_end != -1 and user_end != -1:
                        prefix = message[:user_end+1] + " "
                        content = message[user_end+1:].strip()
                        sender = message[user_start+1:user_end]
                        group_name = message[1:group_end]
                    else:
                        print(message, end='')  # fallback
                        self.chat_history.append(message)
                        return
                else:
                    prefix = message[:prefix_end+2]
                    content = message[prefix_end+2:].strip()
                    sender = message[1:prefix_end]
                    group_name = None
                    
                if content.startswith('ENC:'):
                    print(f"\n[Encrypted]from: {prefix}Message received.")
                    
                    # Try group-specific key first
                    if group_name and group_name in self.group_encryption_keys:
                        try:
                            enc_data = base64.b64decode(content[4:])
                            decrypted = EncryptionUtils.decrypt_message(enc_data, self.group_encryption_keys[group_name])
                            print(f"[Decrypted Group Message] {prefix}{decrypted}")
                            self.chat_history.append(f"[Decrypted Group Message] {prefix}{decrypted}")
                        except Exception:
                            print(f"\n[Group Encrypted Message] from [{sender}] Group Messages received")
                            self.prompt_for_group_decryption(prefix, content, group_name)
                    # Try user-specific key
                    elif sender in self.user_encryption_keys:
                        try:
                            enc_data = base64.b64decode(content[4:])
                            decrypted = EncryptionUtils.decrypt_message(enc_data, self.user_encryption_keys[sender])
                            print(f"[Decrypted Message] {prefix}{decrypted}")
                            self.chat_history.append(f"[Decrypted Message] {prefix}{decrypted}")
                        except Exception:
                            print("Failed to decrypt message with user-specific key.")
                            self.prompt_for_decryption(prefix, content, sender)
                    # Fall back to global key
                    elif self.encryption_enabled and self.encryption_key:
                        try:
                            enc_data = base64.b64decode(content[4:])
                            decrypted = EncryptionUtils.decrypt_message(enc_data, self.encryption_key)
                            print(f"[Decrypted Message] {prefix}{decrypted}")
                            self.chat_history.append(f"[Decrypted Message] {prefix}{decrypted}")
                        except Exception:
                            print("Failed to decrypt message with current key.")
                            self.prompt_for_decryption(prefix, content, sender)
                    else:
                        self.prompt_for_decryption(prefix, content, sender)
                else:
                    print(message, end='')
                    self.chat_history.append(message)
            else:
                print(message, end='')
                self.chat_history.append(message)
        except Exception as e:
            print(f"\nError processing message: {e}")

    def prompt_for_decryption(self, prefix, content, sender=None):
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
                # If sender is specified, store the key for future messages
                if sender:
                    self.user_encryption_keys[sender] = key
                    print(f"Stored encryption key for {sender}")
                break
            except Exception:
                print("Wrong password. Try again.")

    def prompt_for_group_decryption(self, prefix, content, group_name):
        """Prompt user for password to decrypt a group message."""
        while True:
            password = input(f"Enter password to decrypt for group messages: ")
            if password.lower() == "skip":
                print("Skipping decryption.")
                break

            try:
                enc_data = base64.b64decode(content[4:])
                salt = b'salt_'
                key = EncryptionUtils.generate_key(password, salt)
                decrypted = EncryptionUtils.decrypt_message(enc_data, key)
                print(f"[Decrypted Group Message] {prefix}{decrypted}")
                # Store the key for future messages from this group
                self.group_encryption_keys[group_name] = key
                print(f"Stored encryption key for group {group_name}")
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
                        
                        # Prompt for encrypted message
                        message = input("Enter encrypted message to send: ")
                        if message:
                            try:
                                encrypted = EncryptionUtils.encrypt_message(message, self.encryption_key)
                                formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                                self.sock.sendall(formatted_msg.encode('utf-8'))
                                print("Encrypted message sent.")
                                self.chat_history.append(f"[You] {formatted_msg}")
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
            elif tokens[1].lower() == 'user' and len(tokens) >= 3:
                target_user = tokens[2]
                print(f"Setting up encryption for user: {target_user}")
                password = input(f"Enter encryption password for {target_user}: ")
                if password:
                    try:
                        salt = b'salt_'
                        user_key = EncryptionUtils.generate_key(password, salt)
                        self.user_encryption_keys[target_user] = user_key
                        print(f"User-specific encryption enabled for {target_user}")
                        
                        # Wait for user to type the message
                        message = input(f"Enter encrypted message for {target_user} (or type 'done' to finish): ")
                        if message.lower() != 'done':
                            try:
                                encrypted = EncryptionUtils.encrypt_message(message, user_key)
                                formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                                self.sock.sendall(f"@{target_user} {formatted_msg}".encode('utf-8'))
                                print(f"[Encrypted] Message sent to {target_user}.")
                                self.chat_history.append(f"[You] @{target_user} {formatted_msg}")
                            except Exception as e:
                                print(f"Encryption failed: {e}")
                        return True
                    except Exception as e:
                        print(f"Failed to setup user encryption: {e}")
                        return False
                else:
                    print("No password provided. User encryption not enabled.")
                    return False
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
            
            if len(parts) > 1:
                message = parts[1]
                # Check if we have a specific encryption key for this user
                if recipient in self.user_encryption_keys:
                    try:
                        encrypted = EncryptionUtils.encrypt_message(message, self.user_encryption_keys[recipient])
                        formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                        self.sock.sendall(f"@{recipient} {formatted_msg}".encode('utf-8'))
                        print(f"Encrypted private message sent to {recipient}.")
                        self.chat_history.append(f"[You] @{recipient} {formatted_msg}")
                    except Exception as e:
                        print(f"Encryption failed: {e}")
                # If no specific key, use global encryption if enabled
                elif self.encryption_enabled and self.encryption_key:
                    try:
                        encrypted = EncryptionUtils.encrypt_message(message, self.encryption_key)
                        formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                        self.sock.sendall(f"@{recipient} {formatted_msg}".encode('utf-8'))
                        print(f"Encrypted private message sent to {recipient}.")
                        self.chat_history.append(f"[You] @{recipient} {formatted_msg}")
                    except Exception as e:
                        print(f"Encryption failed: {e}")
                else:
                    self.sock.sendall(' '.join(tokens).encode('utf-8'))
                    print(f"Private message sent to {recipient}.")
                    self.chat_history.append(f"[You] @{recipient} {message}")
        except Exception as e:
            print(f"Error sending private message: {e}")

    def handle_group_command(self, tokens):
        """Handle group-related commands with optional encryption."""
        try:
            if len(tokens) < 2:
                print("Invalid group command.")
                return
            
            subcommand = tokens[1].lower()
            
            # Handle group encryption setup
            if subcommand == 'encrypt' and len(tokens) >= 3:
                group_name = tokens[2]
                print(f"Setting up encryption for group: {group_name}")
                password = input(f"Enter encryption password for group {group_name}: ")
                if password:
                    try:
                        salt = b'salt_'
                        group_key = EncryptionUtils.generate_key(password, salt)
                        self.group_encryption_keys[group_name] = group_key
                        print(f"Group encryption enabled for {group_name}")
                        
                        # Prompt for encrypted message immediately after setup
                        message = input(f"Enter encrypted message for group {group_name}: ")
                        if message:
                            try:
                                encrypted = EncryptionUtils.encrypt_message(message, group_key)
                                formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                                self.sock.sendall(f"@group send {group_name} {formatted_msg}".encode('utf-8'))
                                print(f"Encrypted message sent to group {group_name}.")
                                self.chat_history.append(f"[Group {group_name}] [You] {formatted_msg}")
                            except Exception as e:
                                print(f"Group encryption failed: {e}")
                        return True
                    except Exception as e:
                        print(f"Failed to setup group encryption: {e}")
                else:
                    print("No password provided. Group encryption not enabled.")
                return True

            # Handle encrypted group message sending
            if subcommand == 'send' and len(tokens) >= 4:
                group_name = tokens[2]
                message_body = ' '.join(tokens[3:])
                
                # Check if group has encryption enabled
                if group_name in self.group_encryption_keys:
                    try:
                        encrypted = EncryptionUtils.encrypt_message(message_body, self.group_encryption_keys[group_name])
                        formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                        self.sock.sendall(f"@group send {group_name} {formatted_msg}".encode('utf-8'))
                        print(f"Encrypted message sent to group {group_name}.")
                        self.chat_history.append(f"[Group {group_name}] [You] {formatted_msg}")
                    except Exception as e:
                        print(f"Group encryption failed: {e}")
                else:
                    # Send unencrypted message
                    self.sock.sendall(' '.join(tokens).encode('utf-8'))
                    print(f"Message sent to group {group_name}.")
                    self.chat_history.append(f"[Group {group_name}] [You] {message_body}")
            else:
                # Handle other group commands normally
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
                return self.handle_encryption_command(tokens)

            # Handle salt command
            if command.startswith('@salt'):
                if self.handle_salt_command(tokens):
                    return True
                return True

            # Handle standard commands
            if command in ['@names', '@history', '@help', '@quit']:
                if command == '@history':
                    while True:
                        print("\nChat History Menu:")
                        print("1. All Chat History")
                        print("2. Group Chat History")
                        print("3. Chat History with Specific Person")
                        print("4. Back to Chat")
                        
                        choice = input("\nEnter your choice (1-4): ").strip()
                        
                        if choice == '1':
                            print("\nAll Chat History:")
                            print("=" * 30)
                            if self.chat_history:
                                for msg in self.chat_history:
                                    msg = msg.strip()
                                    if not msg.endswith('\n'):
                                        msg += '\n'
                                    print(msg, end='')
                            else:
                                print("No chat history found.")
                            print("=" * 30)
                            
                        elif choice == '2':
                            print("\nGroup Chat History:")
                            print("=" * 30)
                            # Filter for group messages (messages with [groupname][username] format)
                            group_messages = []
                            for msg in self.chat_history:
                                # Check for group message format: [groupname][username] message
                                if msg.count('[') >= 2 and msg.count(']') >= 2:
                                    first_bracket_end = msg.find(']')
                                    second_bracket_start = msg.find('[', first_bracket_end + 1)
                                    if second_bracket_start != -1:
                                        group_messages.append(msg)
                            
                            if group_messages:
                                for msg in group_messages:
                                    msg = msg.strip()
                                    if not msg.endswith('\n'):
                                        msg += '\n'
                                    print(msg, end='')
                            else:
                                print("No group chat history found.")
                            print("=" * 30)
                            
                        elif choice == '3':
                            username = input("\nEnter username to view chat history with: ").strip()
                            print(f"\nChat History with {username}:")
                            print("=" * 30)
                            # Filter for direct messages with the specified user
                            user_messages = []
                            for msg in self.chat_history:
                                # Check for direct messages (both sent and received)
                                if (f"[{username}]" in msg or  # Messages from the user
                                    f"[You] @{username}" in msg or  # Messages sent to the user
                                    (msg.startswith("[PM from") and username in msg) or  # Private messages from the user
                                    (msg.startswith("[PM to") and username in msg)):  # Private messages to the user
                                    user_messages.append(msg)
                            
                            if user_messages:
                                for msg in user_messages:
                                    msg = msg.strip()
                                    if not msg.endswith('\n'):
                                        msg += '\n'
                                    print(msg, end='')
                            else:
                                print(f"No chat history found with {username}.")
                            print("=" * 30)
                            
                        elif choice == '4':
                            break
                        else:
                            print("Invalid choice. Please try again.")
                            
                elif command == '@quit':
                    print("You have quit the chat.")
                    return False
                else:
                    self.sock.sendall(user_input.encode('utf-8'))
                return True

            # Handle group commands
            if command.startswith('@group'):
                self.handle_group_command(tokens)
                return True

            # Handle private messages
            if command.startswith('@'):
                self.handle_private_message(tokens)
                return True
            
            # Handle file transfer commands
            if command in ['@sendfile', '@sendfile-group']:
                self.handle_file_transfer_command(tokens)
                return True
            
            # Handle file transfer responses
            if command in ['@acceptfile', '@rejectfile']:
                self.sock.sendall(user_input.encode('utf-8'))
                return True
            
            # Handle view file command
            if command == '@viewfile':
                if len(tokens) < 2:
                    print("Usage: @viewfile <filename>")
                    return True
                self.view_file_contents(tokens[1])
                return True

            # Handle regular messages with encryption if enabled
            if self.encryption_enabled and self.encryption_key:
                try:
                    encrypted = EncryptionUtils.encrypt_message(user_input, self.encryption_key)
                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                    self.sock.sendall(formatted_msg.encode('utf-8'))
                    print("Message sent (encrypted).")
                    self.chat_history.append(f"[You] {formatted_msg}")
                except Exception as e:
                    print(f"Encryption failed: {e}")
            else:
                self.sock.sendall(user_input.encode('utf-8'))
                self.chat_history.append(f"[You] {user_input}")
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