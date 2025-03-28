# server.py (Cleaned)
import socket
import sys
import threading
import re
from collections import defaultdict
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct
import hashlib
import os
import signal  # Import the signal module
import time # Added for shutdown sleep
import traceback # For detailed error printing

HOST = '0.0.0.0'  # Listen on all available interfaces

COMMANDS_HELP = """
Available Commands:
@quit - Disconnect from the server.
@names - List all online users.
@username <message> - Send a private message.
@group set <group_name> <members> - Create a group. e.g., group set Group 1 Alice Bob
@group add <group_name> <members> - Add users to a group.
@group send <group_name> <message> - Send a message to a group.
@group leave <group_name> - Leave a group.
@group delete <group_name> - Delete a group.
@group encrypt <group_name> - Encrypt a group message in a group.
@history - View chat history.
@help - Show this help message. 

Encryption Commands:
@encrypt on - Starts an encryption session
@encrypt user <username> - Encrypts a message for a specific user 
@encrypt off - Stops the encryption session

File Transfer Commands:
@sendfile <filename> <recipient> - Send a file to a specific user.
@acceptfile - Accept a pending file transfer.
@rejectfile - Reject a pending file transfer.
@viewfile <filename> - View contents of a text file (if it exists in your folder or downloads).
"""


# --- Encryption Utilities ---
def generate_key(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'salt_', iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encrypt_message(message, password):
    fernet = generate_key(password)
    return fernet.encrypt(message.encode('utf-8'))

def decrypt_message(encrypted_message, password):
    try:
        fernet = generate_key(password)
        return fernet.decrypt(encrypted_message).decode('utf-8')
    except:
        return None

def format_encrypted_message(encrypted_data):
    return f"ENC:{base64.b64encode(encrypted_data).decode('utf-8')}"

def parse_encrypted_message(message):
    if message.startswith('ENC:'):
        try:
            enc_data = base64.b64decode(message[4:])
            return True, enc_data
        except:
            return False, message
    return False, message
# --- End Encryption Utilities ---


# --- Group Management ---
class Group:
    def __init__(self, name, creator):
        self.name = name
        self.members = set([creator])
        self.creator = creator
        self.messages = []
    def add_member(self, username): self.members.add(username)
    def remove_member(self, username): self.members.discard(username)
    def is_member(self, username): return username in self.members
    def add_message(self, sender, message): self.messages.append((sender, message))

class GroupManager:
    def __init__(self):
        self.groups = {}
    def create_group(self, group_name, creator):
        if group_name in self.groups: return False, "Group already exists"
        self.groups[group_name] = Group(group_name, creator)
        return True, f"Group '{group_name}' created"
    def delete_group(self, group_name, requester):
        if group_name not in self.groups: return False, "Group does not exist"
        group = self.groups[group_name]
        if requester != group.creator: return False, "Only the group creator can delete the group"
        del self.groups[group_name]
        return True, f"Group '{group_name}' deleted"
    def add_member(self, group_name, username):
        if group_name not in self.groups: return False, "Group does not exist"
        self.groups[group_name].add_member(username)
        return True, f"Added {username} to {group_name}"
    def remove_member(self, group_name, username):
        if group_name not in self.groups: return False, "Group does not exist"
        group = self.groups[group_name]
        if not group.is_member(username): return False, "User is not a member of this group"
        group.remove_member(username)
        return True, f"Removed {username} from {group_name}"
    def send_message(self, group_name, sender, message, client_manager):
        if group_name not in self.groups: return False, "Group does not exist"
        group = self.groups[group_name]
        if not group.is_member(sender): return False, "You are not a member of this group"
        group.add_message(sender, message)
        formatted_message = f"[{group_name}][{sender}] {message}\n"
        for member in list(group.members):
            if not client_manager.send_message(member, formatted_message):
                 print(f"Failed to send group message to {member} (maybe disconnected).")
        return True, "Message sent"
# --- End Group Management ---

# --- Server-Side Client Representation ---
class Client:
    HEADER_FORMAT = "!Q"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.username = None
        self.chat_history = []

    def send_message(self, message):
        """Send string message to this client."""
        try:
            if not message.endswith('\n'):
                message += '\n'
            self.socket.sendall(message.encode('utf-8'))
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"Error sending message to {self.username or self.address}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error sending message to {self.username or self.address}: {e}")
            return False

    def send_bytes(self, data_bytes):
         """Send raw bytes to this client."""
         try:
             self.socket.sendall(data_bytes)
             return True
         except (BrokenPipeError, ConnectionResetError, OSError) as e:
             print(f"Error sending bytes to {self.username or self.address}: {e}")
             return False
         except Exception as e:
            print(f"Unexpected error sending bytes to {self.username or self.address}: {e}")
            return False

    def close(self):
        """Close client connection."""
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except (OSError, Exception):
             pass
        try:
            self.socket.close()
        except (OSError, Exception):
             pass
# --- End Server-Side Client Representation ---


# --- Client Manager ---
class ClientManager:
    def __init__(self):
        self.clients = {}  # Maps username -> Client object
        self.group_manager = GroupManager()
        self.active_transfers = {} # sender_username -> transfer_info

    def add_client(self, username, client):
        if username in self.clients: return False
        self.clients[username] = client
        return True

    def broadcast(self, message, sender_username=None):
        """Broadcast message to all clients except sender."""
        for username, client in list(self.clients.items()):
            if username != sender_username:
                if not client.send_message(message):
                     print(f"Broadcast failed for {username}, removing client.")
                     self.remove_client(username)

    def send_message(self, username, message):
        """Send message to specific client. Returns False on failure."""
        client = self.clients.get(username)
        if client:
            if not client.send_message(message):
                 print(f"Send failed for {username}, removing client.")
                 self.remove_client(username)
                 return False
            return True
        return False

    def send_private(self, sender, recipient, message):
        """Send private message."""
        recipient_client = self.clients.get(recipient)
        sender_client = self.clients.get(sender)

        if not recipient_client:
            if sender_client: sender_client.send_message(f"Error: User '{recipient}' not found.\n")
            return False, "User not found"

        recipient_message = f"[PM from {sender}] {message}\n"
        sender_message = f"[PM to {recipient}] Message sent.\n" # Confirmation to sender

        if not recipient_client.send_message(recipient_message):
             if sender_client: sender_client.send_message(f"Error: Failed to send message to {recipient}.\n")
             self.remove_client(recipient)
             return False, "Recipient disconnected"

        if sender_client:
             sender_client.send_message(sender_message)

        return True, "Message sent"

    # --- Transfer Management Methods ---
    def start_transfer(self, sender_username, recipient_client):
        # Warning for overlapping transfers can be kept if useful, or removed if too noisy
        # if sender_username in self.active_transfers:
        #     print(f"Warning: Sender {sender_username} starting new transfer while previous one might be active.")
        self.active_transfers[sender_username] = {
            'recipient_client': recipient_client,
            'filesize': None,
            'received_bytes': 0,
            'hash': None
        }
        # print(f"Transfer initiated. Sender: {sender_username} -> Recipient: {recipient_client.username}") # Removed Debug

    def get_transfer_info(self, sender_username):
        return self.active_transfers.get(sender_username)

    def update_transfer_header(self, sender_username, filesize, hash_str):
        """Store filesize and hash after receiving header."""
        if sender_username in self.active_transfers:
            self.active_transfers[sender_username]['filesize'] = filesize
            self.active_transfers[sender_username]['hash'] = hash_str
            return True
        return False

    def update_transfer_progress(self, sender_username, received_increment):
        """Update received bytes count. Returns current total."""
        if sender_username in self.active_transfers:
            self.active_transfers[sender_username]['received_bytes'] += received_increment
            return self.active_transfers[sender_username]['received_bytes']
        return 0

    def complete_transfer(self, sender_username):
        """Remove tracking for a completed or cancelled transfer."""
        if sender_username in self.active_transfers:
            # recipient_username = self.active_transfers[sender_username]['recipient_client'].username # Removed Debug
            # print(f"Transfer completed/removed for Sender: {sender_username} -> Recipient: {recipient_username}") # Removed Debug
            del self.active_transfers[sender_username]
        # else: # Removed Debug Warning
             # print(f"Warning: complete_transfer called for non-active/unknown sender: {sender_username}")

    def remove_client(self, username):
        """Override remove_client to also clean up transfers."""
        disconnected_client = self.clients.get(username)

        # Clean up if the disconnected user was a sender
        if username in self.active_transfers:
            # print(f"Cleaning up active transfer initiated by disconnected user {username}.") # Removed Debug
            transfer_info = self.active_transfers[username]
            recipient_client = transfer_info.get('recipient_client')
            if recipient_client and recipient_client.username in self.clients:
                 recipient_client.send_message(f"\nFile transfer cancelled: Sender {username} disconnected.\n")
            del self.active_transfers[username]

        # Clean up if the disconnected user was a recipient
        active_senders = list(self.active_transfers.keys())
        for sender in active_senders:
             transfer_info = self.active_transfers.get(sender)
             if transfer_info and transfer_info.get('recipient_client') == disconnected_client:
                  # print(f"Cleaning up active transfer where recipient {username} disconnected (Sender was {sender}).") # Removed Debug
                  sender_client_obj = self.clients.get(sender)
                  if sender_client_obj:
                       sender_client_obj.send_message(f"\nFile transfer cancelled: Recipient {username} disconnected.\n")
                  del self.active_transfers[sender]

        # Original remove logic
        if username in self.clients:
            client_to_remove = self.clients[username]
            del self.clients[username]
            client_to_remove.close()
# --- End Client Manager ---


# --- Client Handler Thread ---
class ClientHandler:
    def __init__(self, client_sock, addr, client_manager):
        self.client = Client(client_sock, addr)
        self.client_manager = client_manager

    def setup_username(self):
        """Handle initial username setup and validation."""
        retries = 3
        try:
            while retries > 0:
                self.client.socket.sendall(b"Enter a unique username: ")
                self.client.socket.settimeout(60.0)
                username_bytes = self.client.socket.recv(1024)
                self.client.socket.settimeout(None)
                if not username_bytes: return False # Disconnected

                username = username_bytes.decode('utf-8').strip()

                if not username or not re.match("^[A-Za-z0-9_]+$", username):
                    self.client.socket.sendall(b"Invalid username. Use only letters, numbers, underscores.\n")
                    retries -= 1
                    continue

                if not self.client_manager.add_client(username, self.client):
                    self.client.socket.sendall(b"Username is already taken. Please try another.\n")
                    retries -= 1
                    continue

                self.client.username = username
                print(f"[+] {username} connected from {self.client.address}")
                self.client_manager.broadcast(f"{username} has joined the chat.\n", username)
                self.client.send_message("Welcome to the chat!\n")
                return True
            # Failed after retries
            self.client.socket.sendall(b"Too many invalid username attempts. Disconnecting.\n")
            return False
        except socket.timeout:
             print(f"Timeout waiting for username from {self.client.address}. Disconnecting.")
             return False
        except (UnicodeDecodeError, ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"Error during username setup for {self.client.address}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error during username setup for {self.client.address}: {e}")
            traceback.print_exc()
            return False


    def handle_standard_commands(self, tokens):
        """Handle standard commands like @quit, @names, @history, @help."""
        command = tokens[0].lower()
        sender_username = self.client.username

        if command == '@quit':
            return False # Signal to stop handler loop
        elif command == '@names':
            online_users = ", ".join(self.client_manager.clients.keys())
            self.client.send_message(f"Online users: {online_users}\n")
        elif command == '@history':
             self.client.send_message("Server-side history not implemented. Use client history.\n")
        elif command == '@help':
            self.client.send_message(COMMANDS_HELP)
        return True # Keep connection alive

    def handle_group_command(self, tokens):
        """Handle group commands using GroupManager."""
        sender_username = self.client.username
        if len(tokens) < 2:
             self.client.send_message("Usage: @group <set|send|leave|delete|...> ...\n")
             return

        subcommand = tokens[1].lower()
        group_name = tokens[2] if len(tokens) > 2 else None
        message_body = ' '.join(tokens[3:]) if len(tokens) > 3 else None

        if subcommand == 'set' and group_name and len(tokens) >= 3:
            members = set(tokens[3:]) if len(tokens) > 3 else set()
            members.add(sender_username)
            success, msg = self.client_manager.group_manager.create_group(group_name, sender_username)
            if success:
                 self.client.send_message(msg + '\n')
                 added_count = 0
                 for member_name in members:
                      if member_name != sender_username:
                          if member_name in self.client_manager.clients:
                               success_add, msg_add = self.client_manager.group_manager.add_member(group_name, member_name)
                               if success_add:
                                    self.client_manager.send_message(member_name, f"You have been added to group '{group_name}' by {sender_username}.\n")
                                    added_count += 1
                               else:
                                    self.client.send_message(f"Error adding {member_name}: {msg_add}\n")
                          else:
                                self.client.send_message(f"Note: User '{member_name}' not found/online to add to group.\n")
                 self.client.send_message(f"Added {added_count} other members.\n")
            else:
                 self.client.send_message(msg + '\n')

        elif subcommand == 'send' and group_name and message_body:
            success, msg = self.client_manager.group_manager.send_message(
                group_name, sender_username, message_body, self.client_manager
            )
            if not success: self.client.send_message(msg + '\n')

        elif subcommand == 'leave' and group_name:
            success, msg = self.client_manager.group_manager.remove_member(group_name, sender_username)
            self.client.send_message(msg + '\n')
            if success:
                 group = self.client_manager.group_manager.groups.get(group_name)
                 if group:
                     notification = f"{sender_username} has left the group '{group_name}'.\n"
                     for member in list(group.members):
                         self.client_manager.send_message(member, notification)

        elif subcommand == 'delete' and group_name:
            group = self.client_manager.group_manager.groups.get(group_name)
            if group:
                 remaining_members = list(group.members)
                 success, msg = self.client_manager.group_manager.delete_group(group_name, sender_username)
                 self.client.send_message(msg + '\n')
                 if success:
                      notification = f"Group '{group_name}' has been deleted by {sender_username}.\n"
                      for member_name in remaining_members:
                           if member_name != sender_username:
                               self.client_manager.send_message(member_name, notification)
            else:
                 self.client.send_message("Group does not exist.\n")
        elif subcommand == 'add' and len(tokens) >= 3:
            members = set(tokens[3:]) if len(tokens) > 3 else set()
            members.add(sender_username)
            if self.client_manager.group_manager.groups and group_name in self.client_manager.group_manager.groups:
                 added_count = 0
                 for member_name in members:
                      if member_name != sender_username:
                          if member_name in self.client_manager.clients:
                               success_add, msg_add = self.client_manager.group_manager.add_member(group_name, member_name)
                               if success_add:
                                    self.client_manager.send_message(member_name, f"You have been added to group '{group_name}' by {sender_username}.\n")
                                    added_count += 1
                               else:
                                    self.client.send_message(f"Error adding {member_name}: {msg_add}\n")
                          else:
                                self.client.send_message(f"Note: User '{member_name}' not found/online to add to group.\n")
                 self.client.send_message(f"Added {added_count} other members.\n")
            else:
                 self.client.send_message("Error: Group does not exist" + '\n')


    def handle_file_transfer(self, tokens):
        """Handle file transfer initiation command (@sendfile, @sendfile-group)."""
        sender_username = self.client.username
        if len(tokens) < 3:
            self.client.send_message("Usage: @sendfile <filename> <recipient> or @sendfile-group <filename> <group_name>\n")
            return

        command = tokens[0].lower()
        filename = tokens[1]
        target_name = tokens[2]

        if command == '@sendfile':
            recipient_client = self.client_manager.clients.get(target_name)
            if not recipient_client:
                self.client.send_message(f"User '{target_name}' not found or not online.\n")
                return

            if hasattr(recipient_client, 'pending_file_transfer'):
                 self.client.send_message(f"User '{target_name}' already has a pending file transfer offer.\n")
                 return

            offer_msg = f"[FILE] {sender_username} is sending you file '{filename}'. Type @acceptfile to accept or @rejectfile to reject.\n"
            if self.client_manager.send_message(target_name, offer_msg):
                 recipient_client.pending_file_transfer = {
                     'filename': filename,
                     'sender': sender_username,
                     'sender_client': self.client
                 }
                 self.client.send_message(f"File offer sent to {target_name}.\n")
            else:
                 self.client.send_message(f"Failed to send file offer to {target_name}.\n")

        elif command == '@sendfile-group':
             group = self.client_manager.group_manager.groups.get(target_name)
             if not group:
                  self.client.send_message(f"Group '{target_name}' does not exist.\n")
                  return
             if not group.is_member(sender_username):
                  self.client.send_message(f"You are not a member of group '{target_name}'.\n")
                  return

             sent_count = 0
             failed_users = []
             for member_name in list(group.members):
                 if member_name == sender_username: continue

                 recipient_client = self.client_manager.clients.get(member_name)
                 if recipient_client:
                      if hasattr(recipient_client, 'pending_file_transfer'):
                           failed_users.append(f"{member_name} (busy)")
                           continue

                      offer_msg = f"[FILE] {sender_username} (in group {target_name}) is sending file '{filename}'. Type @acceptfile or @rejectfile.\n"
                      if self.client_manager.send_message(member_name, offer_msg):
                           recipient_client.pending_file_transfer = {
                               'filename': filename,
                               'sender': sender_username,
                               'sender_client': self.client,
                               'group': target_name
                           }
                           sent_count += 1
                      else:
                           failed_users.append(member_name)
                 else:
                      failed_users.append(f"{member_name} (offline)")

             self.client.send_message(f"File offer sent to {sent_count} group members.\n")
             if failed_users:
                  self.client.send_message(f"Could not send offer to: {', '.join(failed_users)}.\n")
        else:
             self.client.send_message("Internal error: Invalid file transfer command.\n")


    def handle_file_response(self, command):
        """Handle file transfer response (@acceptfile/@rejectfile) from recipient."""
        recipient_client = self.client

        has_pending = hasattr(recipient_client, 'pending_file_transfer')
        if not has_pending:
            recipient_client.send_message("No pending file transfers.\n")
            return

        transfer_info = recipient_client.pending_file_transfer
        sender_client_obj = transfer_info.get('sender_client')
        sender_username = transfer_info.get('sender')
        filename = transfer_info.get('filename')

        if not sender_client_obj or not sender_username or not filename:
             print(f"Error processing file transfer response for {recipient_client.username} (invalid state).")
             recipient_client.send_message("Error processing file transfer response (invalid state).\n")
             if hasattr(recipient_client, 'pending_file_transfer'): delattr(recipient_client, 'pending_file_transfer')
             return

        if sender_username not in self.client_manager.clients:
             print(f"Sender {sender_username} disconnected before transfer for {recipient_client.username} accepted/rejected.")
             recipient_client.send_message(f"Sender {sender_username} is no longer connected.\n")
             delattr(recipient_client, 'pending_file_transfer')
             return

        if command == '@acceptfile':
            self.client_manager.start_transfer(sender_username, recipient_client)

            sender_client_obj.send_message(f"{recipient_client.username} accepted the file transfer for '{filename}'. Starting transfer...\n")
            recipient_client.send_message(f"Accepting file transfer for '{filename}'...\n")

            # Signal BOTH sender and receiver (based on user's working fix)
            sender_client_obj.send_message("FILE_TRANSFER_START\n")
            recipient_client.send_message("FILE_TRANSFER_START\n")

        elif command == '@rejectfile':
            sender_client_obj.send_message(f"{recipient_client.username} rejected the file transfer for '{filename}'.\n")
            recipient_client.send_message(f"Rejected file transfer for '{filename}'.\n")

        delattr(recipient_client, 'pending_file_transfer')


    def handle_message(self, message):
        """Process incoming decoded messages (commands or chat)."""
        tokens = message.split()
        if not tokens: return True

        command = tokens[0]

        if command in ['@quit', '@names', '@history', '@help']:
            return self.handle_standard_commands(tokens)

        if command.startswith('@group'):
            self.handle_group_command(tokens)
            return True

        if command in ['@sendfile', '@sendfile-group']:
            self.handle_file_transfer(tokens)
            return True

        if command in ['@acceptfile', '@rejectfile']:
            self.handle_file_response(command)
            return True

        if command.startswith('@'):
            recipient = command[1:]
            pm_body = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
            if recipient and recipient in self.client_manager.clients:
                success, msg = self.client_manager.send_private(self.client.username, recipient, pm_body)
                if not success: self.client.send_message(f"Error sending PM to {recipient}: {msg}\n")
            else: self.client.send_message(f"Error: User '{recipient}' not found or invalid command.\n")
            return True

        # Broadcast regular messages
        broadcast_message = f"[{self.client.username}] {message}\n"
        self.client_manager.broadcast(broadcast_message, self.client.username)

        return True

    def run(self):
        """Main handler loop. Handles messages OR proxies file data."""
        if not self.setup_username():
            try:
                self.client.socket.close()
            except: pass
            print(f"Failed username setup or immediate disconnect for {self.client.address}. Handler exiting.")
            return

        sender_username = self.client.username
        unprocessed_data = b''

        while True:
            try:
                new_data = self.client.socket.recv(2048)

                if not new_data and not unprocessed_data:
                    break # Client disconnected

                current_data = unprocessed_data + new_data
                unprocessed_data = b''
                print(f"Processing buffer size: {len(current_data)}") # Kept this print

                transfer_info = self.client_manager.get_transfer_info(sender_username)

                if transfer_info:
                    # --- Proxy Logic ---
                    recipient_client = transfer_info.get('recipient_client')
                    if not recipient_client or recipient_client.username not in self.client_manager.clients:
                        print(f"Transfer cancelled: Recipient for {sender_username} disconnected.")
                        self.client.send_message("File transfer cancelled: Recipient disconnected.\n")
                        self.client_manager.complete_transfer(sender_username)
                        continue

                    data_to_process = current_data

                    # Check if header/hash still needed
                    if transfer_info['filesize'] is None:
                        min_expected_len = Client.HEADER_SIZE + 32
                        if len(data_to_process) < min_expected_len:
                            unprocessed_data = data_to_process
                            continue

                        header = data_to_process[:Client.HEADER_SIZE]
                        hash_bytes = data_to_process[Client.HEADER_SIZE: min_expected_len]
                        remaining_data = data_to_process[min_expected_len:]

                        try:
                            filesize = struct.unpack(Client.HEADER_FORMAT, header)[0]
                            hash_str = hash_bytes.decode('utf-8')
                            # print(f"Received Header (Size={filesize}), Hash ({hash_str})") # Removed Debug
                            if filesize < 0: raise ValueError("Invalid filesize")
                            self.client_manager.update_transfer_header(sender_username, filesize, hash_str)

                            # Forward header & hash
                            if not recipient_client.send_bytes(header): raise ConnectionError("Recipient disconnected on header")
                            if not recipient_client.send_bytes(hash_bytes): raise ConnectionError("Recipient disconnected on hash")

                            data_to_process = remaining_data

                        except (struct.error, UnicodeDecodeError, ValueError, ConnectionError) as e:
                            print(f"Transfer error for {sender_username} (header/hash): {e}. Aborting.")
                            try: recipient_client.send_message(f"Transfer failed: {e}\n")
                            except: pass
                            self.client_manager.complete_transfer(sender_username)
                            continue

                    # Forward file chunk data
                    if data_to_process:
                        fs = transfer_info.get('filesize')
                        total_received = transfer_info.get('received_bytes', 0)
                        if fs is None:
                            print(f"Filesize not set for transfer from {sender_username}. Aborting.")
                            self.client_manager.complete_transfer(sender_username)
                            continue

                        bytes_needed = fs - total_received
                        actual_data_to_forward = data_to_process[:bytes_needed]
                        unprocessed_data = data_to_process[bytes_needed:]
                        # if unprocessed_data: # Removed Debug print about extra bytes
                        #    print(f"Buffering {len(unprocessed_data)} extra bytes received from {sender_username} after expected filesize.")

                        if actual_data_to_forward:
                            if not recipient_client.send_bytes(actual_data_to_forward):
                                print(f"Recipient connection error forwarding chunk from {sender_username}. Cancelling.")
                                self.client.send_message(f"Transfer failed: Recipient connection error.\n")
                                self.client_manager.complete_transfer(sender_username)
                                continue
                            else:
                                self.client_manager.update_transfer_progress(sender_username, len(actual_data_to_forward))

                    # Check completion
                    fs = transfer_info.get('filesize')
                    if fs is not None and transfer_info['received_bytes'] >= fs:
                        # print(f"Transfer complete ({transfer_info['received_bytes']}/{fs} bytes) from {sender_username}.") # Removed Debug
                        self.client_manager.complete_transfer(sender_username)

                else:
                    # --- Handle Regular Messages/Commands ---
                    full_buffer = current_data
                    message_text = ""
                    try:
                        last_newline = full_buffer.rfind(b'\n')
                        if last_newline != -1:
                            lines_to_process_bytes = full_buffer[:last_newline + 1]
                            unprocessed_data = full_buffer[last_newline + 1:]
                            message_text = lines_to_process_bytes.decode('utf-8')
                        else:
                            unprocessed_data = full_buffer
                            message_text = ""

                        if message_text:
                            lines = message_text.splitlines()
                            for line in lines:
                                msg = line.strip()
                                if msg:
                                    # print(f"Decoded message line for {sender_username}: '{msg}'") # Removed Debug
                                    if not self.handle_message(msg):
                                        raise ConnectionAbortedError("Quit command received")
                        # else: # Removed Debug print for no newline case
                             # if not unprocessed_data and not new_data:
                             #    print(f"Received data from {sender_username} with no newline and connection closed?")
                             #    break


                    except UnicodeDecodeError:
                        print(f"UnicodeDecodeError for {sender_username}. Discarding buffer: {repr(full_buffer)}") # Kept Warning
                        unprocessed_data = b''
                    except ConnectionAbortedError:
                        # print(f"Quit command processed for {sender_username}.") # Removed Debug
                        break

            # --- Outer exception handling ---
            except ConnectionResetError:
                # print(f"Connection reset by peer for {sender_username}."); # Removed Debug
                break
            except OSError as e:
                # print(f"Socket Error in run loop for {sender_username}: {e}"); # Removed Debug
                break
            except Exception as e:
                print(f"Exception in client thread ({sender_username}): {e}"); traceback.print_exc(); break

        # --- Loop exited ---
        # print(f"Exiting run loop for {sender_username}.") # Removed Debug
        try:
            self.client.socket.close()
        except: pass
        self.client_manager.remove_client(sender_username) # remove_client now handles dict deletion
        print(f"[-] {sender_username or self.client.address} disconnected.")


# --- Main Server Logic ---
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <port>")
        sys.exit(1)
    try:
        port = int(sys.argv[1])
        if not (0 < port < 65536): raise ValueError("Port out of range")
    except ValueError as e:
        print(f"Invalid port: {sys.argv[1]}. {e}")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, port))
    except OSError as e:
        print(f"Error binding to {HOST}:{port} - {e}")
        sys.exit(1)

    server_socket.listen(5)
    client_manager = ClientManager()
    print(f"Server started on port {port}. Waiting for connections...")

    shutdown_event = threading.Event()
    def signal_handler(sig, frame):
        print("\nCtrl+C detected. Server is shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    active_threads = []
    server_socket.settimeout(1.0)

    while not shutdown_event.is_set():
        try:
            client_sock, addr = server_socket.accept()
            print(f"\n[+] Accepted connection from {addr}")
            client_sock.settimeout(None)
            handler = ClientHandler(client_sock, addr, client_manager)
            t = threading.Thread(target=handler.run, daemon=True)
            t.start()
            active_threads.append(t)

        except socket.timeout:
            continue
        except OSError as e:
            if shutdown_event.is_set():
                 print("Server socket closed during shutdown.")
            else:
                 print(f"Error accepting connection: {e}")
            break
        except Exception as e:
            print(f"Unexpected error accepting connection: {e}")
            traceback.print_exc()
            break

    # --- Shutdown Sequence ---
    print("Server accept loop finished. Cleaning up...")
    try:
         server_socket.close()
         print("Server socket closed.")
    except Exception as e:
         print(f"Error closing server socket: {e}")

    print("Notifying connected clients of shutdown...")
    usernames = list(client_manager.clients.keys())
    for username in usernames:
         # Use send_message which handles potential errors
         client_manager.send_message(username, "Server is shutting down...\n")
         # remove_client will be called eventually by thread exit, or force close if needed
         # client_manager.remove_client(username) # Avoid potential double close

    print("Waiting briefly for client threads...")
    time.sleep(1)

    print("Server shutdown complete.")

if __name__ == "__main__":
    main()
# --- End Main Server Logic ---