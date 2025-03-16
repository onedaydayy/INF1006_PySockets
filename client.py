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
    return encrypted_message

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    """Decrypts a message using Fernet."""
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

# Global Encryption State 
encryption_enabled = False
encryption_key = None

# Message Receiver 

def receive_messages(sock):
    """
    Continuously listen for server messages.
    If encryption is enabled, try to decrypt messages that follow the user message format.
    """
    global encryption_enabled, encryption_key
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("Disconnected from server.")
                break

            # All messages are sent as UTF-8–encoded text.
            message = data.decode('utf-8')
            
            # If encryption is active, assume that chat messages from other users
            # are in the format: "[<prefix>] <encrypted_text>" (for broadcast, PM, or group messages).
            # Control or system messages (that do not start with '[') are printed as is.
            if encryption_enabled:
                if message.startswith('['):
                    idx = message.find("] ")
                    if idx != -1:
                        prefix = message[:idx+2]  # e.g. "[Alice] " or "[PM from Bob] "
                        enc_text = message[idx+2:].strip()
                        try:
                            # Try to decrypt the text.
                            decrypted_msg = decrypt_message(enc_text.encode('utf-8'), encryption_key)
                            print(f"{prefix}{decrypted_msg}")
                        except Exception as de:
                            # If decryption fails, fallback to printing the raw message.
                            print(f"Decryption Error: {de}\nRaw message: {message}")
                    else:
                        print(message, end="")
                else:
                    print(message, end="")
            else:
                print(message, end="")

        except Exception as e:
            print(f"\nConnection lost or error: {e}")
            break

    sock.close()
    sys.exit(0)

# Main Client Function 
def main():
    global encryption_enabled, encryption_key
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

    # Start the thread to listen for messages from the server.
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    print("Connected to server. Type your messages or commands below.")
    try:
        while True:
            user_input = input('')
            if not user_input:
                continue
            lower_input = user_input.strip().lower()
            # Encryption Control Commands (sent as plain text) 
            if lower_input == '@encrypt on':
                password = input("Enter encryption password: ")
                salt = os.urandom(16)  # Generate a random salt
                encryption_key = generate_key(password, salt)
                # Send the salt to the server so that others may share the key if desired.
                sock.sendall(f"@salt {base64.b64encode(salt).decode('utf-8')}".encode('utf-8'))
                encryption_enabled = True
                print("Encryption enabled.")
                continue
            elif lower_input == '@encrypt off':
                encryption_enabled = False
                encryption_key = None
                print("Encryption disabled.")
                sock.sendall(user_input.encode('utf-8'))
                continue
            elif lower_input.startswith('@salt'):
                # When another user sends a salt, you can choose to join encryption.
                parts = user_input.split()
                if len(parts) >= 2:
                    received_salt = base64.b64decode(parts[1])
                    password = input("Enter encryption password: ")
                    encryption_key = generate_key(password, received_salt)
                    encryption_enabled = True
                    print("Encryption is enabled with the shared key.")
                sock.sendall(user_input.encode('utf-8'))
                continue

            # Control Commands (sent as plain text) 
            # Commands like @names, @history, and @quit must be sent without encryption.
            if lower_input in ['@names', '@history', '@quit']:
                sock.sendall(user_input.encode('utf-8'))
                if lower_input == '@quit':
                    print("You have quit the chat.")
                    break
                continue

            # Group commands:
            if lower_input.startswith('@group'):
                tokens = user_input.split()
                if len(tokens) < 2:
                    print("Invalid group command.")
                    continue
                # For group send, we encrypt the message portion if encryption is enabled.
                if tokens[1].lower() == 'send':
                    if len(tokens) < 4:
                        print("Invalid group send command format. Use: @group send <groupName> <message>")
                        continue
                    groupname = tokens[2]
                    message_body = ' '.join(tokens[3:])
                    if encryption_enabled:
                        encrypted_msg = encrypt_message(message_body, encryption_key)
                        # The encrypted text is decoded using latin-1 so that it can be embedded in a UTF-8 string.
                        sock.sendall(f"@group send {groupname} {encrypted_msg.decode('latin-1')}".encode('utf-8'))
                    else:
                        sock.sendall(user_input.encode('utf-8'))
                else:
                    # For other group commands (set, leave, delete), send as plain text.
                    sock.sendall(user_input.encode('utf-8'))
                continue

            # Private messages:
            # If a message starts with '@' (but not '@group' or an encryption command), assume it's a private message.
            if user_input.startswith('@'):
                tokens = user_input.split()
                if len(tokens) < 2:
                    print("Invalid private message format. Use: @username <message>")
                    continue
                # Here, if encryption is enabled, encrypt the message body.
                if encryption_enabled:
                    recipient = tokens[0][1:]
                    message_body = ' '.join(tokens[1:])
                    encrypted_msg = encrypt_message(message_body, encryption_key)
                    sock.sendall(f"@{recipient} {encrypted_msg.decode('latin-1')}".encode('utf-8'))
                else:
                    sock.sendall(user_input.encode('utf-8'))
                continue

            # Broadcast Messages 
            # For regular messages (broadcast), if encryption is enabled then encrypt them.
            if encryption_enabled:
                encrypted_msg = encrypt_message(user_input, encryption_key)
                # Send the encrypted broadcast message as text.
                # The server will prepend the sender’s name, so the final format becomes:
                #   "[username] <encrypted_text>\n"
                sock.sendall(encrypted_msg.decode('latin-1').encode('utf-8'))
            else:
                sock.sendall(user_input.encode('utf-8'))

    except KeyboardInterrupt:
        print("Closing client...")

    sock.close()

if __name__ == "__main__":
    main()
