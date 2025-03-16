# server.py (FIXED)
import socket
import sys
import threading
import re
from collections import defaultdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

HOST = '0.0.0.0'

clients = {}  # username -> socket
groups = {}  # groupName -> set of usernames
chat_history = defaultdict(list)  # username -> list of messages
encryption_keys = {}  # username -> key (TEMPORARY storage)


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

def encrypt_message(message: str, key: bytes) -> bytes:
    """Encrypts a message using Fernet (AES)."""
    f = Fernet(key)
    return f.encrypt(message.encode('utf-8'))

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    """Decrypts a message using Fernet."""
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode('utf-8')

def broadcast(message, sender=None, encrypt=False):
    """Sends a message to all connected clients, except the sender."""
    for user, sock in list(clients.items()):
        if user != sender:
            try:
                if encrypt and sender in encryption_keys and user in encryption_keys:
                    # Only encrypt if BOTH users have matching keys.
                    if encryption_keys[sender] == encryption_keys[user]: # direct compare
                        encrypted_msg = encrypt_message(message, encryption_keys[sender])
                        # Wrap the ENTIRE message (including sender)
                        sock.sendall(f"[{sender}] ".encode('utf-8') + encrypted_msg + b"\n") # send as bytes
                    else:
                        continue  # Key mismatch - don't send
                else:
                    sock.sendall(message.encode('utf-8') + b'\n')  # always add newline

            except Exception as e:
                print(f"Failed to send to {user}: {e}")
    if sender:
        chat_history[sender].append(message)  # Store message in history


def send_private(sender, recipient, msg):
    """Sends a private message to a specific user."""
    if recipient not in clients:
        clients[sender].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
        return

    try:
        if sender in encryption_keys and recipient in encryption_keys:
            # Check for key match before encrypting.
            if encryption_keys[sender] == encryption_keys[recipient]: # direct compare
                encrypted_msg = encrypt_message(msg, encryption_keys[sender])
                full_message = f"[PM from {sender}] ".encode('utf-8') + encrypted_msg + b"\n" # send as bytes
                clients[recipient].sendall(full_message)
            else:
                clients[sender].sendall(b"Encryption key mismatch. Cannot send PM.\n")
                return  # Don't send if keys don't match
        else:
            # Send unencrypted if no keys are set up.
            full_message = f"[PM from {sender}] {msg}\n"
            clients[recipient].sendall(full_message.encode('utf-8'))

        chat_history[sender].append(f"[PM to {recipient}] {msg}")
        chat_history[recipient].append(f"[PM from {sender}] {msg}")

    except Exception as e:
        print(f"Failed to send PM to {recipient}: {e}")



def handle_group_command(sender, tokens_original):
    """Handles group-related commands."""
    tokens_lower = [t.lower() for t in tokens_original]  # Case-insensitive commands
    if len(tokens_lower) < 3:
        clients[sender].sendall(b"Invalid @group command format.\n")
        return

    subcommand, group_name = tokens_lower[1], tokens_original[2]

    if subcommand == 'set':
        if len(tokens_original) < 4:
            clients[sender].sendall(b"No members specified.\n")
            return
        members = ' '.join(tokens_original[3:]).replace(',', ' ').split()  # Handle comma/space separated
        if sender not in members:
            members.append(sender)  # Always include the creator
        if group_name in groups:
            clients[sender].sendall(f"Group '{group_name}' already exists.\n".encode('utf-8'))
            return
        groups[group_name] = set(members)
        clients[sender].sendall(f"Group '{group_name}' created: {', '.join(members)}\n".encode('utf-8'))
        # Notify other members
        for user in members:
            if user != sender and user in clients:
                try:
                    clients[user].sendall(f"Added to group '{group_name}' by {sender}.\n".encode('utf-8'))
                except:
                    print(f"Failed to notify {user}")

    elif subcommand == 'send':
        if group_name not in groups or sender not in groups[group_name]:
            clients[sender].sendall(f"Group/membership error.\n".encode('utf-8'))
            return
        message_body = ' '.join(tokens_original[3:])

        # Check if *all* members of the group share the sender's key.
        can_encrypt = all(sender in encryption_keys and user in encryption_keys and encryption_keys[sender] == encryption_keys[user] for user in groups[group_name]) # direct compare
        if can_encrypt:
             full_message = f"[{sender} -> {group_name}] ".encode('utf-8') + encrypt_message(message_body, encryption_keys[sender]) + b"\n" # send as bytes
             clients[sender].sendall(full_message) # send to group
        else:
            full_message = f"[{sender} -> {group_name}] {message_body}\n"
            for user in groups[group_name]:
                if user in clients:
                    try:
                        clients[user].sendall(full_message.encode('utf-8')) # send all
                    except:
                        print(f"Failed to send to {user}")
                    chat_history[user].append(full_message)

    elif subcommand == 'leave':
        if group_name not in groups or sender not in groups[group_name]:
            clients[sender].sendall(f"Group/membership error.\n".encode('utf-8'))
            return
        groups[group_name].remove(sender)
        clients[sender].sendall(f"Left group '{group_name}'.\n".encode('utf-8'))
        # Notify remaining members
        for user in groups[group_name]:
            if user in clients:
                try:
                    clients[user].sendall(f"{sender} left group '{group_name}'.\n".encode('utf-8'))
                except:
                    print(f"Failed to notify {user}")
        # Delete group if empty
        if not groups[group_name]:
            del groups[group_name]
            print(f"Group '{group_name}' deleted (empty).")

    elif subcommand == 'delete':
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' not found.\n".encode('utf-8'))
            return
        # Notify all members
        for user in list(groups[group_name]):
            if user in clients:
                try:
                    clients[user].sendall(f"Group '{group_name}' deleted by {sender}.\n".encode('utf-8'))
                except:
                    print(f"Failed to notify {user}")
        del groups[group_name]  # Delete the group
        clients[sender].sendall(f"Group '{group_name}' deleted.\n".encode('utf-8'))

    else:
        clients[sender].sendall(b"Unknown @group subcommand.\n")

def list_users(requester):
    """Sends the list of connected users to the requester."""
    clients[requester].sendall(f"Online users: {', '.join(clients.keys())}\n".encode('utf-8'))

def handle_client_salt(username, salt_message):
    """Handles receiving and distributing salt for encryption."""

    parts = salt_message.split()
    if len(parts) != 2:
        return  # Invalid format

    try:
        received_salt = base64.b64decode(parts[1])
    except Exception as e:
        print(f"Error decoding salt from {username}: {e}")
        return

    # Notify all *other* connected users.
    for other_user, other_sock in clients.items():
        if other_user != username:
            try:
                other_sock.sendall(f"@{username} salt {parts[1]}\n".encode('utf-8'))
            except Exception as e:
                print(f"Failed to send salt to {other_user}: {e}")

def handle_set_encryption(username, message):
    """Handles the 'set encryption' command."""
    tokens_lower = message.lower().split()
    if len(tokens_lower) == 4 and tokens_lower[0] == 'set' and tokens_lower[1] == 'encryption':
        user_from = tokens_lower[2]
        key = tokens_lower[3]
        encryption_keys[username] = key.encode('latin-1') # encode as latin-1
        print(f"Set encryption key for user: {username} from: {user_from}")
        clients[username].sendall(f"Encryption is enabled with a shared key from {user_from}.\n".encode('utf-8'))


def process_message(username, message):
    """Processes a received message based on its content."""
    tokens_original = message.split()
    tokens_lower = message.lower().split()

    if tokens_lower[0] == '@quit':
        broadcast(f"{username} left.\n", sender=username)
        return False  # Signal to exit client loop
    elif tokens_lower[0] == '@names':
        list_users(username)
    elif tokens_lower[0] == '@history':
        for msg in chat_history[username]:
            clients[username].sendall(msg.encode('utf-8'))
    elif tokens_lower[0] == '@help':
        clients[username].sendall(COMMANDS_HELP.encode('utf-8'))
    elif tokens_lower[0] == '@salt':
        handle_client_salt(username, message)
    elif tokens_lower[0] == 'set' and tokens_lower[1] == 'encryption' and len(tokens_lower) == 4:
        handle_set_encryption(username, message)
    elif tokens_lower[0].startswith('@group'):
        handle_group_command(username, tokens_original)
    elif tokens_lower[0].startswith('@'):
        recipient = tokens_original[0][1:]
        pm_body = ' '.join(tokens_original[1:])
        send_private(username, recipient, pm_body)
    else:
        broadcast(message, sender=username, encrypt=True)
    return True  # Continue client loop

def cleanup_client(username):
    """Performs cleanup operations when a client disconnects."""
    for group_name, members in list(groups.items()):
        if username in members:
            members.remove(username)
            for other_user in members:
                if other_user in clients:
                    try:
                        clients[other_user].sendall(f"{username} left group '{group_name}' (disconnected).\n".encode('utf-8'))
                    except:
                        pass
            if not members:
                del groups[group_name]

    if username in encryption_keys:
        del encryption_keys[username]

    if username in clients:
        del clients[username]
    print(f"[-] {username} disconnected")


def initialize_client(client_sock, addr):
    """Initializes a new client connection."""
    client_sock.sendall(b"Enter username: ")
    username = client_sock.recv(1024).decode('utf-8').strip()

    if not username or not re.match("^[A-Za-z0-9_]+$", username) or username in clients:
        client_sock.sendall(b"Invalid/duplicate username.\n")
        client_sock.close()
        return None  # Indicate failure

    clients[username] = client_sock
    print(f"[+] {username} connected ({addr})")
    broadcast(f"{username} joined.\n", sender=username)
    client_sock.sendall(b"Welcome!\n")
    return username

def client_thread(client_sock, addr):
    """Handles a single client connection."""
    try:
        username = initialize_client(client_sock, addr)
        if username is None:
            return  # Initialization failed

        while True:
            try:
                data = client_sock.recv(1024)
                if not data:
                    break
                message = data.decode('utf-8').strip()
                if not message:
                    continue

                if not process_message(username, message):
                    break  # process_message indicated to exit

            except ConnectionResetError:
                break
            except Exception as e:
                print(f"Error in thread ({username}): {e}")
                break
    finally:
        if username: # if username is defined
            cleanup_client(username)
        if client_sock: # if client_sock is defined
          client_sock.close()



COMMANDS_HELP = """
Available commands:
@quit - Disconnect from the server.
@names - List all connected users.
@<username> <message> - Send a private message to the specified user.
@group set <groupname> <user1, user2, ...> - Create a new group.
@group send <groupname> <message> - Send a message to a group.
@group leave <groupname> - Leave a group.
@group delete <groupname> - Delete a group.
@history - Display your chat history.
@help - Show this help message.
@encrypt on - Initiate encrypted communication.
"""

def main():
    """Main server loop."""
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
    server_socket.bind((HOST, port))
    server_socket.listen(5)  # Listen for up to 5 connections
    print(f"Server started on port {port}. Waiting for connections...")

    try:
        while True:
            client_sock, addr = server_socket.accept()  # Accept new connection
            client_thread_instance = threading.Thread(
                target=client_thread,
                args=(client_sock, addr),
                daemon=True  # Allow main program to exit even if threads are running
            )
            client_thread_instance.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        # Notify all connected clients
        for _, sock in list(clients.items()):
            try:
                sock.sendall(b"Server shutting down.\n")
                sock.close()
            except:
                pass  # Don't crash if sending fails
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()