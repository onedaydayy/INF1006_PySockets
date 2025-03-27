# client.py (Cleaned)
import socket
import sys
import threading # Make sure threading is imported
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
import time # Import time for sleep/timeouts
import traceback # Import traceback for better error reporting


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
        # Ensure input is bytes
        if isinstance(encrypted_message, str):
             if encrypted_message.startswith("ENC:"):
                  encrypted_message = encrypted_message[4:] # Remove prefix
             try:
                  encrypted_message_bytes = base64.b64decode(encrypted_message)
             except base64.binascii.Error as b64_err:
                  raise Exception(f"Base64 decode error: {b64_err} on input {repr(encrypted_message)}") from b64_err
        elif isinstance(encrypted_message, bytes):
             if encrypted_message.startswith(b"ENC:"):
                 encrypted_message_bytes = base64.b64decode(encrypted_message[4:])
             else:
                 encrypted_message_bytes = base64.b64decode(encrypted_message)
        else:
             raise TypeError(f"decrypt_message expects bytes or base64 string, got {type(encrypted_message)}")

        try:
            f = Fernet(key)
            decrypted_bytes = f.decrypt(encrypted_message_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            # Keep this error print as it indicates a failure visible to the user
            print(f"\nDecryption Error: {e}")
            return "[Decryption Failed]"


class Client:
    # File transfer constants
    CHUNK_SIZE = 8192
    HEADER_FORMAT = "!Q"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, server_host, port):
        self.server_host = server_host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_lock = threading.Lock()
        self.receive_thread = None
        self.is_running = True

        # State variables
        self.encryption_enabled = False
        self.encryption_key = None
        self.encryption_password = None
        self.chat_history = []
        self.user_encryption_keys = {}
        self.group_encryption_keys = {}
        self.username = None
        self.pending_receive_filename = None
        self.pending_send_file = None


    def calculate_md5(self, filepath):
        """Calculate MD5 hash of a file"""
        md5_hash = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except FileNotFoundError:
            print(f"Error (calculate_md5): File not found at {filepath}")
            return None
        except Exception as e:
            print(f"Error (calculate_md5): {e}")
            return None

    # --- Socket Send Helper ---
    def send_sock_message(self, message_bytes: bytes):
        """Helper function to send bytes data with lock."""
        if not self.is_running: return False
        if not isinstance(message_bytes, bytes):
             # Keep this error print as it indicates a programming error
             print(f"ERROR (send_sock_message): Input must be bytes, got {type(message_bytes)}")
             return False
        try:
            with self.socket_lock:
                self.sock.sendall(message_bytes)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"\nConnection error during send: {e}. Shutting down.")
            self.is_running = False
            return False
        except Exception as e:
            print(f"Error sending message: {e}")
            self.is_running = False
            return False

    def send_sock_string(self, message_str: str):
         """Helper to send string, ensuring encoding and newline"""
         if not self.is_running: return False
         if not message_str.endswith('\n'):
              message_str += '\n'
         return self.send_sock_message(message_str.encode('utf-8'))
    # --- End Socket Send Helper ---


    def handle_file_transfer_command(self, tokens):
        """Handle file transfer commands initiation"""
        if len(tokens) < 3:
            print("Usage: @sendfile <filename> <recipient> or @sendfile-group <filename> <group_name>")
            return

        filename = tokens[1]
        abs_filename = os.path.abspath(filename)
        if not os.path.exists(abs_filename):
            print(f"Error: File '{abs_filename}' not found.")
            return

        # Show preview
        try:
            with open(abs_filename, 'r', encoding='utf-8') as f:
                preview = f.read(1024)
                print(f"\nPreview of {abs_filename}:")
                print("=" * 30)
                print(preview)
                if len(preview) == 1024: print("\n... (file continues)")
                print("=" * 30)
        except UnicodeDecodeError:
            print(f"Note: '{os.path.basename(abs_filename)}' is a binary file and cannot be previewed.")
        except Exception as e:
            print(f"Note: Cannot preview file '{abs_filename}': {e}")

        # Send command to server
        command_str = ' '.join(tokens)
        if self.send_sock_string(command_str):
            print(f"File transfer request sent for '{filename}'")
            # Store ABSOLUTE path for sending later
            self.pending_send_file = abs_filename
        else:
             print(f"Error sending file transfer command '{command_str}' to server.")


    def send_file(self, filepath):
        """Send a file over the socket connection, ensuring thread safety."""
        success_flag = False
        try:
            abs_path = os.path.abspath(filepath)
            if not os.path.exists(abs_path):
                raise FileNotFoundError(f"File not found at resolved path: {abs_path}")

            filesize = os.path.getsize(abs_path)
            if filesize < 0:
                 raise ValueError(f"Invalid file size {filesize} for {abs_path}")

            md5_hash = self.calculate_md5(abs_path)
            if md5_hash is None:
                raise Exception("Failed to calculate MD5 hash.")

            with self.socket_lock:
                # Send header
                header_bytes = struct.pack(self.HEADER_FORMAT, filesize)
                self.sock.sendall(header_bytes)

                # Send hash
                self.sock.sendall(md5_hash.encode())

                # Send content
                sent_size = 0
                if filesize > 0:
                    with open(abs_path, "rb") as f:
                        while True:
                            chunk = f.read(self.CHUNK_SIZE)
                            if not chunk:
                                break
                            self.sock.sendall(chunk)
                            sent_size += len(chunk)
                            progress = (sent_size / filesize) * 100
                            print(f"\rSending: {progress:.1f}%", end='', flush=True)
                else:
                    print("\nFilesize is 0, no content chunks to send.")

                # Keep warning for size mismatch
                if sent_size != filesize:
                     print(f"\nWARNING: Sent size ({sent_size}) does not match filesize ({filesize})!")

                print("\nFile metadata and content (if any) sent.")
                success_flag = True

        except FileNotFoundError:
             print(f"\nError sending file: File not found at {filepath}")
             success_flag = False
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
             print(f"\nConnection error during send_file: {e}. Shutting down.")
             self.is_running = False
             success_flag = False
        except Exception as e:
            print(f"\nError sending file: {e}")
            traceback.print_exc() # Keep traceback for unexpected errors
            success_flag = False
        finally:
             return success_flag


    def receive_file(self, filename):
        """Receive a file over the socket connection, ensuring thread safety."""
        saved_successfully = False
        save_path = ""
        received_size = 0
        filesize = -1
        original_timeout = None
        try:
            os.makedirs('downloads', exist_ok=True)
            base_filename = os.path.basename(filename)
            if not base_filename:
                 raise ValueError(f"Invalid filename extracted from path: {filename}")
            save_path = os.path.join('downloads', base_filename)
            # print(f"Saving to path: {save_path}") # Removed Debug

            with self.socket_lock:
                original_timeout = self.sock.gettimeout()
                TRANSFER_RECV_TIMEOUT = 30.0
                self.sock.settimeout(TRANSFER_RECV_TIMEOUT)
                # print(f"Set socket timeout to {TRANSFER_RECV_TIMEOUT}s") # Removed Debug

                header = None
                try:
                    # Receive header
                    header = self.sock.recv(self.HEADER_SIZE)
                    if not header or len(header) < self.HEADER_SIZE:
                        raise Exception(f"Failed to receive complete header (need {self.HEADER_SIZE} bytes). Got: {repr(header)}")

                    filesize = struct.unpack(self.HEADER_FORMAT, header)[0]
                    if filesize < 0: raise ValueError(f"Invalid filesize received: {filesize}")

                    # Receive MD5
                    md5_hash_bytes = self.sock.recv(32)
                    if not md5_hash_bytes or len(md5_hash_bytes) < 32:
                         raise Exception(f"Failed to receive complete MD5 hash (need 32 bytes). Got: {repr(md5_hash_bytes)}")
                    md5_hash = md5_hash_bytes.decode()

                    # Receive content
                    if filesize > 0:
                        with open(save_path, "wb") as f:
                            while received_size < filesize:
                                remaining_size = filesize - received_size
                                chunk_size_to_recv = min(self.CHUNK_SIZE, remaining_size)
                                chunk = self.sock.recv(chunk_size_to_recv)
                                if not chunk:
                                    raise Exception(f"Connection closed unexpectedly after receiving {received_size} / {filesize} bytes.")
                                f.write(chunk)
                                received_size += len(chunk)
                                progress = (received_size / filesize) * 100
                                print(f"\rReceiving: {progress:.1f}%", end='', flush=True)
                    else:
                        # print("Filesize is 0, no content to receive.") # Removed Debug
                        received_size = 0

                except socket.timeout:
                    # Keep this error print
                    print(f"\nERROR: Socket timed out after {TRANSFER_RECV_TIMEOUT}s during receive!")
                    raise
                except Exception as recv_err:
                    # Keep this error print
                    print(f"\nERROR: Error during socket receive: {recv_err}")
                    raise
                finally:
                    # Always restore original timeout
                    # print(f"Restoring original socket timeout ({original_timeout}).") # Removed Debug
                    self.sock.settimeout(original_timeout)

            # Check if received size matches expected size
            if received_size != filesize:
                 raise Exception(f"Transfer incomplete: Received {received_size} bytes, expected {filesize}.")

            # Verify MD5
            # print(f"Verifying MD5 hash...") # Removed Debug
            received_md5 = self.calculate_md5(save_path)
            if received_md5 is None:
                 raise Exception("Failed to calculate MD5 hash of received file.")
            if received_md5 != md5_hash:
                # print(f"MD5 mismatch! Deleting corrupted file: {save_path}") # Removed Debug
                if os.path.exists(save_path):
                    try: os.remove(save_path)
                    except Exception as del_err: print(f"Error deleting corrupted file {save_path}: {del_err}")
                raise Exception("File transfer failed: MD5 verification failed")
            # else: # Removed Debug
                 # print(f"MD5 hash verified successfully.")

            print(f"\nFile received successfully and saved as '{save_path}'")
            saved_successfully = True

        except (BrokenPipeError, ConnectionResetError, OSError) as e:
             print(f"\nConnection error during receive_file: {e}. Shutting down.")
             self.is_running = False
             saved_successfully = False
        except Exception as e:
            # Keep this error print for unexpected issues
            print(f"\nERROR during receive_file: {e}")
            traceback.print_exc()
            saved_successfully = False
        finally:
            # Clean up partially written file if transfer failed
            if save_path and os.path.exists(save_path) and not saved_successfully:
                 if filesize > 0 and received_size < filesize:
                      # print(f"Cleaning up incomplete file: {save_path}") # Removed Debug
                      try: os.remove(save_path)
                      except Exception as del_err: print(f"Error cleaning up incomplete file: {del_err}")

            # Restore timeout just in case
            if original_timeout is not None:
                 try:
                      with self.socket_lock:
                           if self.sock.gettimeout() != original_timeout:
                                self.sock.settimeout(original_timeout)
                 except Exception: pass

            # print(f"Exiting receive_file function. Success={saved_successfully}") # Removed Debug
            return saved_successfully


    def view_file_contents(self, filename):
        """View contents of a file"""
        try:
            filepath = None
            base_filename = os.path.basename(filename)
            downloads_path = os.path.join('downloads', base_filename)
            if os.path.exists(downloads_path):
                filepath = downloads_path
            elif os.path.exists(filename):
                 filepath = filename
            else:
                print(f"Error: File '{base_filename}' not found in downloads folder or as '{filename}'.")
                return False

            file_size = os.path.getsize(filepath)
            if file_size > 1024 * 1024: # 1MB limit for auto-view
                print(f"Warning: File '{os.path.basename(filepath)}' is large ({file_size/1024/1024:.1f}MB).")
                try: response = input("Do you want to continue? (y/n): ").lower()
                except EOFError: print("Input unavailable. Aborting view."); return False
                if response != 'y': return False

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    print(f"\n=== Contents of {os.path.basename(filepath)} ===")
                    print(f.read())
                    print("=" * 30)
                return True
            except UnicodeDecodeError:
                print(f"Error: '{os.path.basename(filepath)}' is binary and cannot be displayed.")
                return False
        except Exception as e:
            print(f"Error viewing file '{filename}': {e}")
            return False


    def connect(self):
        """Establish connection, perform username negotiation, start receive thread."""
        try:
            print(f"Connecting to {self.server_host}:{self.port}...")
            self.sock.connect((self.server_host, self.port))
            print("Connected to server.")
            self.is_running = True

            retries = 3
            while self.is_running and retries > 0:
                try:
                    self.sock.settimeout(60.0)
                    data = self.sock.recv(1024).decode('utf-8').strip()
                    self.sock.settimeout(None)
                    print(f"Server: {data}") # Keep server prompts
                    if "Enter a unique username" in data:
                        while self.is_running:
                            username_input = input("Enter a unique username: ").strip()
                            if not re.match("^[A-Za-z0-9_]+$", username_input):
                                print("Invalid username. Use only letters, numbers, underscores.")
                                continue
                            self.sock.sendall(username_input.encode('utf-8'))
                            self.sock.settimeout(60.0)
                            server_response = self.sock.recv(1024).decode('utf-8').strip()
                            self.sock.settimeout(None)
                            print(f"Server: {server_response}") # Keep server responses
                            if "Username is already taken" in server_response:
                                retries -=1
                                if retries <= 0:
                                     # self.sock.sendall(b"Too many attempts. Disconnecting.\n") # Server handles this
                                     self.is_running = False
                                     return False
                                continue
                            elif "Welcome to the chat" in server_response:
                                self.username = username_input
                                self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                                self.receive_thread.start()
                                # print("Receive thread started. You can now start typing messages.") # Can be inferred
                                return True
                            else:
                                print("Unexpected server response during username setup.")
                                time.sleep(1)
                    elif not data:
                         print("Server disconnected during setup.")
                         self.is_running = False
                         return False
                except socket.timeout:
                     print("Timeout waiting for server during setup.")
                     retries -=1
                     if retries <= 0: self.is_running = False; return False
                except (UnicodeDecodeError, ConnectionResetError, BrokenPipeError, OSError) as e:
                     print(f"Connection error during setup: {e}")
                     self.is_running = False
                     return False
                except Exception as e:
                     print(f"Unexpected error during setup: {e}")
                     traceback.print_exc()
                     self.is_running = False
                     return False

            print("Failed username setup.")
            self.is_running = False
            return False

        except socket.gaierror: print(f"Connection error: Hostname {self.server_host} could not be resolved."); self.is_running = False; return False
        except ConnectionRefusedError: print(f"Connection error: Connection refused by {self.server_host}:{self.port}."); self.is_running = False; return False
        except Exception as e: print(f"Connection error: {e}"); self.is_running = False; return False


    def receive_messages(self):
        """Continuously receive messages from the server in a separate thread."""
        # print("Receive thread started.") # Can be inferred
        while self.is_running:
            data = None
            acquired_lock = False
            try:
                acquired_lock = self.socket_lock.acquire(timeout=0.5)
                if acquired_lock:
                    try:
                         self.sock.settimeout(0.5)
                         data = self.sock.recv(1024)
                         self.sock.settimeout(None)
                    finally:
                         self.socket_lock.release()
                else:
                     time.sleep(0.1)
                     continue

                if not data and acquired_lock:
                    print("\nServer closed connection.")
                    self.is_running = False
                    break
                elif data:
                    try:
                        message = data.decode('utf-8')
                        self.process_message(message)
                    except UnicodeDecodeError:
                        # Keep this warning as it indicates unexpected binary data
                        print(f"Warning: Received non-UTF8 data, ignoring: {repr(data[:80])}")
                        pass

            except socket.timeout:
                 continue
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                 if self.is_running: print(f"\nConnection error in receive_messages: {e}")
                 self.is_running = False
                 break
            except Exception as e:
                if self.is_running: print(f"\nUnexpected error in receive_messages: {e}"); traceback.print_exc()
                self.is_running = False
                break
        # print("Exiting receive loop.") # Removed Debug


    def process_message(self, message):
        """Process potentially bundled messages received from the server."""
        try:
            processed_message = message.replace('\x00', '')
            lines = processed_message.splitlines()
            if not lines and processed_message: lines = [processed_message]
            elif not lines: return

            for line in lines:
                if not line: continue
                message_stripped = line.strip()

                # --- Handle Signals First ---
                if message_stripped == "FILE_TRANSFER_START":
                    # print(f"Detected FILE_TRANSFER_START signal.") # Removed Debug
                    if self.pending_receive_filename is not None:
                        filename_to_receive = self.pending_receive_filename
                        print(f"\nStarting to receive file '{filename_to_receive}'...")
                        success = self.receive_file(filename_to_receive)
                        if success: print(f"\nSuccessfully received {filename_to_receive}.")
                        else: print(f"\nFailed to receive {filename_to_receive}.")
                        self.pending_receive_filename = None
                        # print(f"Cleared self.pending_receive_filename.") # Removed Debug
                    elif self.pending_send_file:
                        filename_to_send = self.pending_send_file
                        print(f"\nStarting file transfer for '{filename_to_send}'...")
                        success = self.send_file(filename_to_send)
                        if success: print(f"\nSuccessfully sent {filename_to_send}.")
                        else: print(f"\nFailed to send {filename_to_send}.")
                        self.pending_send_file = None
                        # print(f"Cleared self.pending_send_file.") # Removed Debug
                    # else: # Removed Debug Warning
                        # print(f"\nWarning: Received FILE_TRANSFER_START but no pending file was set!")
                    continue

                # --- Handle Regular Messages ---
                if line.startswith('[FILE]'):
                    print(line.strip()) # Show file offer
                    self.chat_history.append(line)
                    try:
                        parts = line.split("'")
                        if len(parts) >= 3:
                            self.pending_receive_filename = parts[1]
                            # print(f"(Stored pending receive filename: {self.pending_receive_filename})") # Removed Debug
                    except Exception as e: print(f"(Error parsing filename from offer: {e})")
                    continue

                elif line.startswith('['): # User or Group messages
                    prefix_end = line.find("] ")
                    content, prefix, sender, group_name = "", "", None, None
                    if prefix_end == -1: # Try group format
                        group_end = line.find("]")
                        user_start = line.find("[", group_end + 1)
                        user_end = line.find("]", user_start + 1)
                        if group_end != -1 and user_end != -1:
                            prefix = line[:user_end + 1] + " "
                            content = line[user_end + 1:].strip()
                            sender = line[user_start + 1:user_end]
                            group_name = line[1:group_end]
                        else: print(line.strip()); self.chat_history.append(line); continue # Fallback print
                    else: # User message format
                        prefix = line[:prefix_end + 2]
                        content = line[prefix_end + 2:].strip()
                        sender = line[1:prefix_end]

                    if content.startswith('ENC:'):
                        print(f"[Encrypted] from: {prefix}Message received.") # Keep notice
                        key_to_use, is_group = None, False
                        if group_name and group_name in self.group_encryption_keys: key_to_use, is_group = self.group_encryption_keys[group_name], True
                        elif sender and sender in self.user_encryption_keys: key_to_use = self.user_encryption_keys[sender]
                        elif self.encryption_enabled and self.encryption_key: key_to_use = self.encryption_key
                        if key_to_use:
                            try:
                                decrypted_msg = EncryptionUtils.decrypt_message(content[4:], key_to_use)
                                # Print decrypted message
                                print(f"[Decrypted{' Group' if is_group else ''}] {prefix}{decrypted_msg}")
                                self.chat_history.append(f"[Decrypted{' Group' if is_group else ''}] {prefix}{decrypted_msg}")
                            except Exception as decrypt_err: print(f"Failed to decrypt with stored key: {decrypt_err}")
                        else: print("No key found for encrypted message.")
                    else: # Plaintext
                        print(line.strip()) # Show message
                        self.chat_history.append(line)
                    continue

                # Handle other server messages (joins, leaves, errors etc)
                else:
                    print(line.strip()) # Show other messages
                    self.chat_history.append(line)
                    continue

        except Exception as e:
            print(f"\nError processing received message chunk: {e}")
            traceback.print_exc()


    # --- Methods requiring locking for sendall (using helper) ---

    def handle_encryption_command(self, tokens):
        if len(tokens) >= 2:
            cmd_type = tokens[1].lower()
            if cmd_type == 'on':
                pw = input("Enter encryption password: ")
                if pw:
                    try:
                        salt = b'salt_'
                        self.encryption_key = EncryptionUtils.generate_key(pw, salt)
                        self.encryption_password = pw
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
                    except Exception as e: print(f"Failed to enable encryption: {e}")
                else: print("No password provided.")
            elif cmd_type == 'off':
                 self.encryption_enabled, self.encryption_key, self.encryption_password = False, None, None
                 print("Encryption disabled.")
                 return True
            elif cmd_type == 'user' and len(tokens) >= 3:
                target = tokens[2]
                pw = input(f"Enter encryption password for {target}: ")
                if pw:
                    try:
                        salt = b'salt_'
                        key = EncryptionUtils.generate_key(pw, salt)
                        self.user_encryption_keys[target] = key
                        print(f"User-specific encryption enabled for {target}")
                        return True
                    except Exception as e: print(f"Failed setup user encryption: {e}")
                else: print("No password provided.")
        return False


    def handle_private_message(self, tokens):
        try:
            parts = ' '.join(tokens).split(' ', 1)
            recipient = parts[0][1:]
            if len(parts) < 2: print("Usage: @recipient <message>"); return
            message = parts[1]
            formatted_msg, encrypted = message, False
            key_to_use = self.user_encryption_keys.get(recipient) or (self.encryption_enabled and self.encryption_key)
            if key_to_use:
                try:
                    enc_bytes = EncryptionUtils.encrypt_message(message, key_to_use)
                    formatted_msg = f"ENC:{base64.b64encode(enc_bytes).decode('utf-8')}"
                    encrypted = True
                except Exception as e: print(f"Encryption failed: {e}")
            if self.send_sock_string(f"@{recipient} {formatted_msg}"):
                 print(f"{'Encrypted p' if encrypted else 'P'}rivate message sent to {recipient}.")
                 self.chat_history.append(f"[You] @{recipient} {message if not encrypted else '[Encrypted Msg]'}")
            else: print(f"Failed to send PM to {recipient}.")
        except Exception as e: print(f"Error sending private message: {e}"); traceback.print_exc()

    def handle_group_command(self, tokens):
         try:
             if len(tokens) < 2: print("Invalid group command."); return
             subcommand = tokens[1].lower()
             if subcommand in ['set', 'send', 'leave', 'delete']:
                  group_name = tokens[2] if len(tokens) > 2 else None
                  message_body = ' '.join(tokens[3:]) if len(tokens) > 3 else None
                  msg_to_send = ' '.join(tokens)
                  log_msg = f"Group command '{msg_to_send}' sent."
                  hist_msg = None

                  if subcommand == 'send' and group_name and message_body:
                       key_to_use = self.group_encryption_keys.get(group_name)
                       if key_to_use:
                            try:
                                enc_bytes = EncryptionUtils.encrypt_message(message_body, key_to_use)
                                formatted_enc_msg = f"ENC:{base64.b64encode(enc_bytes).decode('utf-8')}"
                                msg_to_send = f"@group send {group_name} {formatted_enc_msg}"
                                log_msg = f"Encrypted message sent to group {group_name}."
                                hist_msg = f"[Group {group_name}] [You] [Encrypted Msg]"
                            except Exception as e: print(f"Group encryption failed: {e}"); return
                       else:
                            hist_msg = f"[Group {group_name}] [You] {message_body}"

                  if self.send_sock_string(msg_to_send):
                       print(log_msg)
                       if hist_msg: self.chat_history.append(hist_msg)
                  else: print(f"Failed to send group command/message.")

             else: print(f"Unknown group subcommand: {subcommand}")
         except Exception as e: print(f"Error handling group command: {e}"); traceback.print_exc()


    def handle_input(self, user_input):
        """Process user input, route to handlers or send to server."""
        try:
            tokens = user_input.split()
            if not tokens: return True
            command = tokens[0].lower()

            # Local handlers first
            if command == '@history':
                  while True:
                      print("\nChat History Menu:")
                      print("1. All Chat History")
                      print("2. Group Chat History")
                      print("3. Chat History with Specific Person")
                      print("4. Back to Chat")
                      choice = input("Enter your choice (1-4): ").strip()
                      if choice == '1':
                          print("\nAll Chat History:\n" + "=" * 30)
                          for msg in self.chat_history: print(msg.strip())
                          print("=" * 30)
                      elif choice == '2':
                          print("\nGroup Chat History:\n" + "=" * 30)
                          for msg in self.chat_history:
                              if msg.count('[') >= 2 and msg.count(']') >= 2:
                                  first_bracket_end = msg.find(']')
                                  second_bracket_start = msg.find('[', first_bracket_end + 1)
                                  if second_bracket_start != -1: print(msg.strip())
                          print("=" * 30)
                      elif choice == '3':
                          target_user = input("Enter username: ").strip()
                          print(f"\nChat History with {target_user}:\n" + "=" * 30)
                          for msg in self.chat_history:
                              if f"[{target_user}]" in msg or f"@{target_user}" in msg or target_user in msg:
                                  print(msg.strip())
                          print("=" * 30)
                      elif choice == '4': break
                      else: print("Invalid choice.")
                  return True

            if command == '@viewfile':
                 if len(tokens) < 2: print("Usage: @viewfile <filename>")
                 else: self.view_file_contents(tokens[1])
                 return True

            # Routed handlers
            if command == '@encrypt': return self.handle_encryption_command(tokens)
            if command.startswith('@group'): self.handle_group_command(tokens); return True
            if command in ['@sendfile', '@sendfile-group']: self.handle_file_transfer_command(tokens); return True
            if command == "@rejectfile": self.pending_receive_filename = None # Clear state on reject
            if command.startswith('@') and command not in ['@acceptfile', '@rejectfile', '@names', '@help', '@quit']:
                 self.handle_private_message(tokens); return True

            # --- Direct Send or Regular Message ---
            message_to_send = user_input
            is_command = command.startswith('@')

            if not is_command and self.encryption_enabled and self.encryption_key:
                  try:
                      enc_bytes = EncryptionUtils.encrypt_message(user_input, self.encryption_key)
                      message_to_send = f"ENC:{base64.b64encode(enc_bytes).decode('utf-8')}"
                      print("(Sending encrypted)")
                  except Exception as e: print(f"Encryption failed, sending plaintext: {e}")

            # Send using helper
            # print(f"Sending message/command '{message_to_send}' to server.") # Removed Debug
            sent_ok = self.send_sock_string(message_to_send)

            if sent_ok:
                if not is_command: self.chat_history.append(f"[You] {user_input}")
                if command == '@quit':
                     print("You have quit the chat.")
                     self.is_running = False
                     return False
                return True
            else:
                print("Failed to send message/command to server. Disconnecting.")
                self.is_running = False
                return False

        except EOFError: print("\nInput stream closed. Disconnecting..."); self.is_running = False; self.send_sock_string("@quit"); return False
        except Exception as e: print(f"\nError handling input '{user_input}': {e}"); traceback.print_exc(); return True


    def run(self):
        """Main client loop for user input."""
        if not self.is_running: print("Client not connected. Exiting."); return
        print(f"Connected as {self.username}. Enter messages or commands (@help for list).")
        try:
            while self.is_running:
                user_input = input('') # Blocking input
                if not self.is_running: break
                if not user_input.strip(): continue
                if not self.handle_input(user_input): break
        except KeyboardInterrupt: print("\nCtrl+C detected. Disconnecting..."); self.is_running = False; self.send_sock_string("@quit")
        except EOFError: print("\nInput ended (Ctrl+D). Disconnecting..."); self.is_running = False; self.send_sock_string("@quit")
        except Exception as e: print(f"\nUnexpected error in main loop: {e}"); traceback.print_exc(); self.is_running = False
        finally: self.shutdown_client()


    def shutdown_client(self):
        """Cleanly shutdown client resources."""
        if hasattr(self, '_shutdown_called') and self._shutdown_called: return
        self._shutdown_called = True

        print("\nShutting down client...")
        self.is_running = False

        try:
            # print("Attempting to acquire lock for final close...") # Removed Debug
            if self.socket_lock.acquire(timeout=1.0):
                 try:
                     # print("Closing socket.") # Removed Debug
                     self.sock.shutdown(socket.SHUT_RDWR)
                     self.sock.close()
                 except (OSError, Exception) as e: print(f"Error during socket shutdown/close: {e}")
                 finally: self.socket_lock.release()
            else: print("Could not acquire lock to close socket cleanly.")
        except Exception as e: print(f"Error closing socket: {e}")

        if self.receive_thread and self.receive_thread.is_alive():
             # print("Waiting for receive thread...") # Removed Debug
             self.receive_thread.join(timeout=1.5)
             if self.receive_thread.is_alive(): print("Warning: Receive thread did not exit cleanly.")

        print("Client shutdown complete.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python client.py <server_host> <port>")
        sys.exit(1)
    host = sys.argv[1]
    try: port = int(sys.argv[2]); assert 0 < port < 65536
    except (ValueError, AssertionError): print(f"Invalid port number: {sys.argv[2]}."); sys.exit(1)

    client = Client(host, port)
    if client.connect():
        client.run()
    else:
        print("Failed to connect to the server.")