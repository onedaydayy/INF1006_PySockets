import socket
import sys
import threading
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# File Transfer Utilities
class FileTransfer:
    CHUNK_SIZE = 8192
    TIMEOUT = 30  # seconds

    @staticmethod
    def format_size(size):
        """Convert size to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f}{unit}"
            size /= 1024
        return f"{size:.2f}TB"

    @staticmethod
    def show_progress(current, total):
        """Display progress bar"""
        percentage = (current * 100) // total
        bar_length = 30
        filled = int(bar_length * current / total)
        bar = '=' * filled + '-' * (bar_length - filled)
        print(f"\rProgress: [{bar}] {percentage}% ({FileTransfer.format_size(current)}/{FileTransfer.format_size(total)})", end='')
        if current == total:
            print()  # New line when complete

    @staticmethod
    def send_file(sock, filepath):
        """Send a file over the socket"""
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                return False, "File not found"
            
            # Get file size
            filesize = os.path.getsize(filepath)
            print(f"\nSending file: {os.path.basename(filepath)} ({FileTransfer.format_size(filesize)})")
            
            # Send file info
            filename = os.path.basename(filepath)
            file_info = f"{filename}:{filesize}"
            sock.sendall(file_info.encode('utf-8'))
            
            # Wait for ready signal
            response = sock.recv(1024).decode('utf-8')
            if response != "READY":
                return False, "Receiver not ready"
            
            # Send file data in chunks
            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    chunk = f.read(FileTransfer.CHUNK_SIZE)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    bytes_sent += len(chunk)
                    FileTransfer.show_progress(bytes_sent, filesize)
            
            # Wait for confirmation
            response = sock.recv(1024).decode('utf-8')
            if response == "SUCCESS":
                return True, "File sent successfully"
            return False, "File transfer failed"
            
        except Exception as e:
            return False, f"Error sending file: {str(e)}"

    @staticmethod
    def receive_file(sock, save_dir="."):
        """Receive a file over the socket"""
        try:
            # Get file info
            file_info = sock.recv(1024).decode('utf-8')
            filename, filesize = file_info.split(':')
            filesize = int(filesize)
            
            # Ask user for confirmation
            print(f"\nIncoming file: {filename} ({FileTransfer.format_size(filesize)})")
            response = input("Accept file? (yes/no): ").lower()
            
            if response != 'yes':
                sock.sendall("REJECTED".encode('utf-8'))
                return False, "File rejected"
            
            # Send ready signal
            sock.sendall("READY".encode('utf-8'))
            
            # Prepare file path
            filepath = os.path.join(save_dir, filename)
            
            # Create downloads directory if it doesn't exist
            os.makedirs(save_dir, exist_ok=True)
            
            # Check if file already exists
            if os.path.exists(filepath):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(filepath):
                    new_name = f"{base}_{counter}{ext}"
                    filepath = os.path.join(save_dir, new_name)
                    counter += 1
            
            print(f"\nReceiving file: {os.path.basename(filepath)}")
            
            # Receive file data
            with open(filepath, 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    chunk = sock.recv(min(FileTransfer.CHUNK_SIZE, filesize - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    FileTransfer.show_progress(bytes_received, filesize)
            
            # Verify complete transfer
            if bytes_received == filesize:
                sock.sendall("SUCCESS".encode('utf-8'))
                return True, f"File saved as {filepath}"
            else:
                sock.sendall("FAILED".encode('utf-8'))
                return False, "Incomplete transfer"
                
        except Exception as e:
            return False, f"Error receiving file: {str(e)}"

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
        self.file_transfer = FileTransfer()
        self.downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads", "ChatFiles")
        os.makedirs(self.downloads_dir, exist_ok=True)

    def set_downloads_directory(self, directory):
        """Set custom downloads directory"""
        try:
            directory = os.path.expanduser(directory)
            os.makedirs(directory, exist_ok=True)
            self.downloads_dir = directory
            print(f"Downloads directory set to: {directory}")
            return True
        except Exception as e:
            print(f"Error setting downloads directory: {e}")
            return False

    def connect(self):
        """Establish connection to the server and perform username negotiation."""
        try:
            self.sock.connect((self.server_host, self.port))
            buffer = ""
            while True:
                data = self.sock.recv(1024).decode('utf-8')
                buffer += data

                # Handle server responses line-by-line
                while "\n" in buffer or "Enter a unique username:" in buffer:
                    if "Enter a unique username:" in buffer:
                        print("Enter a unique username: ", end='')
                        username = input().strip()
                        self.sock.sendall(username.encode('utf-8'))
                        buffer = ""  # Clear buffer to await next response
                        break
                    elif "Username is already taken" in buffer or "Invalid username" in buffer:
                        print(buffer.strip())
                        buffer = ""  # Wait for next username prompt
                        # Don't break here, allow loop to continue
                    elif "Welcome to the chat" in buffer:
                        print(buffer.strip())
                        buffer = ""
                        threading.Thread(target=self.receive_messages, daemon=True).start()
                        print("You can now start typing your messages.")
                        return
                    else:
                        print(buffer.strip())
                        buffer = ""
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
            # Handle file transfer notifications
            if message.startswith('[FILE]'):
                # File transfer will be handled by FileTransfer class
                return
                
            if message.startswith('['):
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
                    else:
                        print(message, end='')  # fallback
                        return
                else:
                    prefix = message[:prefix_end+2]
                    content = message[prefix_end+2:].strip()
                    
                if content.startswith('ENC:'):
                    print(f"\n[Encrypted]from: {prefix}Message received.")
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
                                    #break
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

    def handle_file_command(self, tokens):
        """Handle file transfer commands"""
        if len(tokens) < 2:
            print("Available file commands:")
            print("  @sendfile <username> <filepath> - Send a file to a user")
            print("  @setdownloads <directory> - Set downloads directory")
            return True

        if tokens[1].lower() == 'setdownloads':
            if len(tokens) < 3:
                print(f"Current downloads directory: {self.downloads_dir}")
                print("Usage: @setdownloads <directory>")
                return True
            directory = ' '.join(tokens[2:])
            self.set_downloads_directory(directory)
            return True

        if len(tokens) < 3:
            print("Usage: @sendfile <username> <filepath>")
            return True

        recipient = tokens[1]
        filepath = ' '.join(tokens[2:])  # Handle filenames with spaces
        
        # Expand user path (e.g., ~/Documents/file.txt)
        filepath = os.path.expanduser(filepath)
        
        # Check file size before sending
        try:
            filesize = os.path.getsize(filepath)
            if filesize > 100 * 1024 * 1024:  # 100MB limit
                print("Warning: Large file detected. Are you sure you want to send it? (yes/no)")
                if input().lower() != 'yes':
                    print("File transfer cancelled.")
                    return True
        except Exception as e:
            print(f"Error checking file: {e}")
            return True
        
        # Send file transfer request
        self.sock.sendall(f"@sendfile {recipient} {os.path.basename(filepath)}".encode('utf-8'))
        
        # Wait for server confirmation
        response = self.sock.recv(1024).decode('utf-8')
        if response.startswith("ERROR:"):
            print(response[6:])  # Print error message
            return True
            
        # Start file transfer
        success, msg = FileTransfer.send_file(self.sock, filepath)
        print(msg)
        return True

    def handle_input(self, user_input):
        """Process user input and handle different types of commands."""
        try:
            tokens = user_input.split()
            if not tokens:
                return True

            command = tokens[0].lower()

            # Handle file transfer command
            if command == '@sendfile':
                return self.handle_file_command(tokens)

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