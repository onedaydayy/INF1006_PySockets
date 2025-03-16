import socket
import sys
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

# Encryption Utilities 
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
    return base64.b64encode(encrypted_message)  # Use base64 encoding to ensure safe transmission

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    """Decrypts a message using Fernet."""
    f = Fernet(key)
    try:
        decoded_message = base64.b64decode(encrypted_message)
        decrypted_message = f.decrypt(decoded_message).decode('utf-8')
        return decrypted_message
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def handle_encryption_setup(sock, password: str, salt: bytes = None):
    """Unified encryption setup handler"""
    global encryption_enabled, encryption_key
    if not salt:
        salt = os.urandom(16)
    encryption_key = generate_key(password, salt)
    encryption_enabled = True
    if salt:
        # Only send salt when creating a new encryption session
        sock.sendall(f"@salt {base64.b64encode(salt).decode('utf-8')}".encode('utf-8'))
    return encryption_key

def prompt_for_password(prefix):
    """Prompt user for password without interrupting their typing"""
    print(f"\n{prefix} - This is an encrypted message.")
    password = input("Enter password to decrypt: ")
    return password

# Add a new global variable to track encryption state
waiting_for_password = False
last_encrypted_message = None
last_prefix = None

def handle_encrypted_message(message: str, prefix: str) -> None:
    """Handle encrypted message by prompting for password"""
    global waiting_for_password, last_encrypted_message, last_prefix
    
    if not message.startswith('ENC:'):
        print(f"{prefix}{message}", end='')
        return
        
    # Store the encrypted message and wait for password
    waiting_for_password = True
    last_encrypted_message = message
    last_prefix = prefix
    
    # Clear the current line and prompt for password
    print(f"\n{prefix}[ENCRYPTED] Message received.")
    print("Enter password to decrypt: ", end='', flush=True)
    
    # Get password from user
    try:
        password = input()
        if password:
            try:
                enc_data = base64.b64decode(message[4:])
                salt = b'salt_'  # Using same salt as server
                key = generate_key(password, salt)
                decrypted = decrypt_message(enc_data, key)
                if decrypted:
                    print(f"{prefix}[DECRYPTED] {decrypted}")
                else:
                    print(f"{prefix}[ENCRYPTED] Failed to decrypt - wrong password?")
            except Exception as e:
                print(f"{prefix}[ENCRYPTED] Failed to decrypt: {str(e)}")
    except:
        print("\nPassword input cancelled")

# Global Encryption State 
encryption_enabled = False
encryption_key = None
encryption_password = None

# Message Receiver 

def receive_messages(sock):
    """
    Continuously listen for server messages.
    Automatically prompt for password when encrypted message is received.
    """
    global encryption_enabled, encryption_key, encryption_password
    
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("\nDisconnected from server")
                break
            
            message = data.decode('utf-8')
            
            # Handle messages that start with a prefix (e.g., "[User] message")
            if message.startswith('['):
                idx = message.find("] ")
                if idx != -1:
                    prefix = message[:idx+2]  # e.g., "[Alice] " or "[PM from Bob] "
                    content = message[idx+2:].strip()
                    
                    # Check if message is encrypted
                    if content.startswith('ENC:'):
                        # Message is encrypted
                        print(f"\n{prefix}[ENCRYPTED] Message received.")
                        
                        # If we're in encryption mode, try using the preset password first
                        if encryption_enabled and encryption_password:
                            try:
                                enc_data = base64.b64decode(content[4:])
                                key = generate_key(encryption_password, b'salt_')
                                decrypted = decrypt_message(enc_data, key)
                                print(f"[Encrypted Chat] {prefix}{decrypted}")
                                continue
                            except:
                                # If preset password didn't work, prompt for a different one
                                pass
                        
                        # Prompt for password
                        password = input("Enter password to decrypt: ")
                        
                        try:
                            enc_data = base64.b64decode(content[4:])
                            salt = b'salt_'  # Using same salt as server
                            key = generate_key(password, salt)
                            decrypted = decrypt_message(enc_data, key)
                            if decrypted:
                                print(f"[Encrypted Chat] {prefix}{decrypted}")
                            else:
                                print(f"{prefix}[ENCRYPTED] Failed to decrypt - wrong password?")
                        except Exception as e:
                            print(f"{prefix}[ENCRYPTED] Failed to decrypt: {str(e)}")
                    else:
                        # Message is not encrypted
                        print(message, end='')
                else:
                    print(message, end='')
            else:
                print(message, end='')
                
        except Exception as e:
            print(f"\nConnection error: {e}")
            break
    sock.close()
    sys.exit(0)

# Main Client Function 
def main():
    global encryption_enabled, encryption_key, encryption_password
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
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
    print("Connected to server. Type your messages or commands below.")
    try:
        while True:
            user_input = input('')
            if not user_input:
                continue
            
            tokens = user_input.split()
            if not tokens:
                continue

            # Handle encryption mode
            if tokens[0].lower() == '@encrypt' and tokens[1].lower() == 'on':
                print("Encryption mode ON")
                print("Please enter encryption password: ", end='', flush=True)
                encryption_password = input()
                if encryption_password:
                    encryption_enabled = True
                    salt = b'salt_'  # Using same salt as server
                    encryption_key = generate_key(encryption_password, salt)
                    print("Encryption enabled. All messages will be encrypted.")
                else:
                    print("No password provided. Encryption not enabled.")
                continue
                
            elif tokens[0].lower() == '@encrypt' and tokens[1].lower() == 'off':
                encryption_enabled = False
                encryption_key = None
                encryption_password = None
                print("Encryption disabled. Messages will be sent in plaintext.")
                continue

            # If encryption is enabled, encrypt all regular messages
            if encryption_enabled and encryption_key and not user_input.startswith('@'):
                try:
                    encrypted = encrypt_message(user_input, encryption_key)
                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                    sock.sendall(formatted_msg.encode('utf-8'))
                    print("Message encrypted and sent.")
                    continue
                except Exception as e:
                    print(f"Encryption failed: {e}")

            # Handle one-time encryption with @encrypt password message
            elif tokens[0].lower() == '@encrypt' and len(tokens) >= 3:
                password = tokens[1]
                message = ' '.join(tokens[2:])
                
                try:
                    salt = b'salt_'  # Using same salt as server
                    key = generate_key(password, salt)
                    encrypted = encrypt_message(message, key)
                    formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                    sock.sendall(formatted_msg.encode('utf-8'))
                    print("Message encrypted and sent.")
                except Exception as e:
                    print(f"Encryption failed: {e}")
                continue

            # Handle regular commands and messages
            elif user_input.startswith('@'):
                # Special handling for private messages in encryption mode
                if encryption_enabled and tokens[0].startswith('@') and len(tokens) > 1 and not tokens[0].lower() in ['@quit', '@names', '@history', '@help']:
                    recipient = tokens[0][1:]
                    message = ' '.join(tokens[1:])
                    try:
                        encrypted = encrypt_message(message, encryption_key)
                        formatted_msg = f"ENC:{base64.b64encode(encrypted).decode('utf-8')}"
                        sock.sendall(f"@{recipient} {formatted_msg}".encode('utf-8'))
                        print("Private message encrypted and sent.")
                    except Exception as e:
                        print(f"Encryption failed: {e}")
                    continue
                else:
                    # Send regular command
                    sock.sendall(user_input.encode('utf-8'))
                    if user_input.lower() == '@quit':
                        print("Disconnecting from server...")
                        break
            else:
                sock.sendall(user_input.encode('utf-8'))

    except KeyboardInterrupt:
        print("\nDisconnecting from server...")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
