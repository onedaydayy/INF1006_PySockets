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

HOST = '0.0.0.0'  # Listen on all available interfaces

COMMANDS_HELP = """
Available Commands:
@quit - Disconnect from the server.
@names - List all online users.
@username <message> - Send a private message.
@everyone <message> - Send a message to all users.
@group set <group_name> <members> - Create a group.
@group send <group_name> <message> - Send a message to a group.
@group leave <group_name> - Leave a group.
@group delete <group_name> - Delete a group.
@history - View chat history.
@help - Show this help message.

Encryption Commands:
@encrypt on - Starts an encryption session
@encrypt off - Stops the encryption session

File Transfer Commands:
@sendfile <filename> <recipient> - Send a file to a specific user.
@sendfile-group <filename> <group_name> - Send a file to all members of a group.
@acceptfile - Accept a pending file transfer.
@rejectfile - Reject a pending file transfer.
@viewfile <filename> - View contents of a text file (if it exists in your folder or downloads).
"""

def generate_key(password):
    """Generate encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encrypt_message(message, password):
    """Encrypt message with password"""
    fernet = generate_key(password)
    return fernet.encrypt(message.encode('utf-8'))

def decrypt_message(encrypted_message, password):
    """Decrypt message with password"""
    try:
        fernet = generate_key(password)
        return fernet.decrypt(encrypted_message).decode('utf-8')
    except:
        return None

def format_encrypted_message(encrypted_data):
    """Format encrypted message for transmission"""
    return f"ENC:{base64.b64encode(encrypted_data).decode('utf-8')}"

def parse_encrypted_message(message):
    """Parse encrypted message"""
    if message.startswith('ENC:'):
        try:
            enc_data = base64.b64decode(message[4:])
            return True, enc_data
        except:
            return False, message
    return False, message

def broadcast(message, sender=None):
    """Deprecated: Use ClientManager.broadcast instead"""
    pass

def send_private(sender, recipient, msg):
    """Deprecated: Use ClientManager.send_private instead"""
    pass

def handle_group_command(sender, tokens_original):
    """Deprecated: Use ClientHandler.handle_group_command instead"""
    pass

def list_users(requester):
    """Deprecated: Use ClientManager.list_users instead"""
    pass

class Group:
    def __init__(self, name, creator):
        self.name = name
        self.members = set([creator])  # Initialize with creator as first member
        self.creator = creator
        self.messages = []  # Store group messages

    def add_member(self, username):
        """Add a member to the group"""
        self.members.add(username)

    def remove_member(self, username):
        """Remove a member from the group"""
        if username in self.members:
            self.members.remove(username)

    def is_member(self, username):
        """Check if user is a member"""
        return username in self.members

    def add_message(self, sender, message):
        """Add message to group history"""
        self.messages.append((sender, message))

class GroupManager:
    def __init__(self):
        self.groups = {}  # Maps group_name -> Group object

    def create_group(self, group_name, creator):
        """Create a new group"""
        if group_name in self.groups:
            return False, "Group already exists"
        
        self.groups[group_name] = Group(group_name, creator)
        return True, f"Group '{group_name}' created"

    def delete_group(self, group_name, requester):
        """Delete a group"""
        if group_name not in self.groups:
            return False, "Group does not exist"
        
        group = self.groups[group_name]
        if requester != group.creator:
            return False, "Only the group creator can delete the group"
        
        del self.groups[group_name]
        return True, f"Group '{group_name}' deleted"

    def add_member(self, group_name, username):
        """Add member to group"""
        if group_name not in self.groups:
            return False, "Group does not exist"
        
        self.groups[group_name].add_member(username)
        return True, f"Added {username} to {group_name}"

    def remove_member(self, group_name, username):
        """Remove member from group"""
        if group_name not in self.groups:
            return False, "Group does not exist"
        
        group = self.groups[group_name]
        if not group.is_member(username):
            return False, "User is not a member of this group"
        
        group.remove_member(username)
        return True, f"Removed {username} from {group_name}"

    def send_message(self, group_name, sender, message, client_manager):
        """Send message to group"""
        if group_name not in self.groups:
            return False, "Group does not exist"
        
        group = self.groups[group_name]
        if not group.is_member(sender):
            return False, "You are not a member of this group"
        
        group.add_message(sender, message)
        formatted_message = f"[{group_name}][{sender}] {message}\n"

        # Send to all group members
        for member in group.members:
            client_manager.send_message(member, formatted_message)
        
        return True, "Message sent"

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
    
    def send_file(self, filepath):
        """Send a file over the socket connection"""
        try:
            # Get file size
            filesize = os.path.getsize(filepath)
            
            # Send filesize header
            self.socket.sendall(struct.pack(self.HEADER_FORMAT, filesize))
            
            # Calculate and send MD5 hash
            md5_hash = self.calculate_md5(filepath)
            self.socket.sendall(md5_hash.encode())
            
            # Send file content
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    self.socket.sendall(chunk)
            
            return True, md5_hash
        except Exception as e:
            return False, str(e)
    
    def receive_file(self, save_path):
        """Receive a file over the socket connection"""
        try:
            # Receive filesize header
            header = self.socket.recv(self.HEADER_SIZE)
            filesize = struct.unpack(self.HEADER_FORMAT, header)[0]
            
            # Receive MD5 hash
            md5_hash = self.socket.recv(32).decode()  # MD5 hash is 32 characters
            
            # Receive and save file
            received_size = 0
            with open(save_path, "wb") as f:
                while received_size < filesize:
                    chunk_size = min(self.CHUNK_SIZE, filesize - received_size)
                    chunk = self.socket.recv(chunk_size)
                    if not chunk:
                        raise Exception("Connection closed before file transfer completed")
                    f.write(chunk)
                    received_size += len(chunk)
            
            # Verify MD5 hash
            received_md5 = self.calculate_md5(save_path)
            if received_md5 != md5_hash:
                os.remove(save_path)  # Delete corrupted file
                raise Exception("File transfer failed: MD5 verification failed")
            
            return True, md5_hash
        except Exception as e:
            return False, str(e)
        
    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.username = None
        self.encryption_enabled = False
        self.encryption_key = None
        self.encryption_password = None
        self.chat_history = []

    def send_message(self, message):
        """Send message to client"""
        try:
            self.socket.sendall(message.encode('utf-8'))
            self.chat_history.append(message)
            return True
        except:
            return False

    def close(self):
        """Close client connection"""
        try:
            self.socket.close()
        except:
            pass

class ClientManager:
    def __init__(self):
        self.clients = {}  # Maps username -> Client object
        self.group_manager = GroupManager()
        self.chat_history = defaultdict(list)  # Moved from global

    def add_client(self, username, client):
        """Add new client"""
        if username in self.clients:
            return False
        self.clients[username] = client
        return True

    def remove_client(self, username):
        """Remove client"""
        if username in self.clients:
            self.clients[username].close()
            del self.clients[username]

    def broadcast(self, message, sender=None):
        """Broadcast message to all clients except sender"""
        for username, client in self.clients.items():
            if username != sender:
                client.send_message(message)

    def send_message(self, username, message):
        """Send message to specific client"""
        if username in self.clients:
            return self.clients[username].send_message(message)
        return False

    def send_private(self, sender, recipient, message):
        """Send private message"""
        if recipient not in self.clients:
            return False, "User not found"
        
        # Send message to recipient
        recipient_message = f"[PM from {sender}] {message}\n"
        self.clients[recipient].send_message(recipient_message)
        
        # Send confirmation to sender
        sender_message = f"[PM to {recipient}] Message sent.\n"
        self.clients[sender].send_message(sender_message)
        
        # Add to both users' chat history
        self.add_to_history(recipient, recipient_message)
        self.add_to_history(sender, sender_message)
        
        return True, "Message sent"

    def get_user_history(self, username):
        """Get chat history for a user"""
        return self.chat_history[username]

    def add_to_history(self, username, message):
        """Add message to user's chat history"""
        self.chat_history[username].append(message)

    def list_users(self, requester):
        """List all online users"""
        names_str = ", ".join(self.clients.keys())
        self.clients[requester].send_message(f"Online users: {names_str}\n")

class ClientHandler:
    def __init__(self, client_sock, addr, client_manager):
        self.client = Client(client_sock, addr)
        self.client_manager = client_manager
        
    def setup_username(self):
        """Handle initial username setup and validation"""
        while True:  # Keep trying until a valid username is provided
            try:
                self.client.socket.sendall(b"Enter a unique username: ")
                username = self.client.socket.recv(1024).decode('utf-8').strip()
                
                if not username or not re.match("^[A-Za-z0-9_]+$", username):
                    self.client.socket.sendall(b"Invalid username. Please try again with only letters, numbers, and underscores.\n")
                    continue  # Ask for username again

                if not self.client_manager.add_client(username, self.client):
                    self.client.socket.sendall(b"Username is already taken. Please try another username.\n")
                    continue  # Ask for username again

                self.client.username = username
                print(f"[+] {username} connected from {self.client.address}")
                self.client_manager.broadcast(f"{username} has joined the chat.\n", username)
                self.client.send_message("Welcome to the chat!\n")
                return True

            except Exception as e:
                print(f"Error during initial username setup: {e}")
                return False  # Only return False on connection errors

    # def handle_encryption_command(self, tokens):
    #     """Handle @encrypt and @decrypt commands"""
        
    #     # Decrypt message - command is nothing but a function to decrypt message.
    #     if tokens[0].lower() == '@decrypt':
    #         if len(tokens) < 3:
    #             self.client.socket.sendall(b"Usage: @decrypt password encrypted_message\n")
    #             return
            
    #         password = tokens[1]
    #         enc_message = ' '.join(tokens[2:])
            
    #         is_encrypted, enc_data = parse_encrypted_message(enc_message)
    #         if not is_encrypted:
    #             self.client.socket.sendall(b"Not a valid encrypted message.\n")
    #             return
            
    #         try:
    #             decrypted = decrypt_message(enc_data, password)
    #             if decrypted:
    #                 self.client.socket.sendall(f"Decrypted message: {decrypted}\n".encode('utf-8'))
    #             else:
    #                 self.client.socket.sendall(b"Failed to decrypt. Wrong password?\n")
    #         except:
    #             self.client.socket.sendall(b"Decryption failed. Invalid message format.\n")

    def handle_standard_commands(self, tokens):
        """Handle standard commands like @quit, @names, @history, etc."""
        command = tokens[0].lower()
        if command == '@quit':
            self.client_manager.broadcast(f"{self.client.username} has left the chat.\n", self.client.username)
            return False
        elif command == '@names':
            self.client_manager.list_users(self.client.username)
        elif command == '@history':
            history = self.client_manager.get_user_history(self.client.username)
            if history:
                for msg in history:
                    self.client.socket.sendall(msg.encode('utf-8'))
            else:
                self.client.socket.sendall(b"No chat history found.\n")
        elif command == '@help':
            self.client.socket.sendall(COMMANDS_HELP.encode('utf-8'))
        return True

    def handle_group_command(self, tokens):
        """Handle group commands using GroupManager"""
        if len(tokens) < 3:
            self.client.send_message("Invalid @group command format.\n")
            return

        subcommand = tokens[1].lower()
        group_name = tokens[2]

        if subcommand == 'set':
            if len(tokens) < 4:
                self.client.send_message("No members specified for group set.\n")
                return

            member_string = ' '.join(tokens[3:])
            members = member_string.replace(',', ' ').split()
            if self.client.username not in members:
                members.append(self.client.username)

            success, msg = self.client_manager.group_manager.create_group(group_name, self.client.username)
            if success:
                for member in members:
                    if member in self.client_manager.clients:  # Only add existing users
                        success_add, msg_add = self.client_manager.group_manager.add_member(group_name, member)
                        if success_add:
                            # Notify the member about being added to the group
                            self.client_manager.send_message(member, f"You have been added to group '{group_name}'.\n")
                        else:
                            self.client.send_message(f"Failed to add {member}: {msg_add}\n")
                    else:
                        self.client.send_message(f"User '{member}' not found.\n")

                # Send group creation confirmation to creator
                self.client.send_message(f"Group '{group_name}' created with members: {', '.join(members)}\n")
            else:
                self.client.send_message(f"{msg}\n")

        elif subcommand == 'send':
            if len(tokens) < 4:
                self.client.send_message("No message provided.\n")
                return
                
            message_body = ' '.join(tokens[3:])
            group = self.client_manager.group_manager.groups.get(group_name)
            if not group:
                self.client.send_message(f"Group '{group_name}' does not exist.\n")
                return
            if not group.is_member(self.client.username):
                self.client.send_message(f"You are not a member of '{group_name}'.\n")
                return

            # Updated group message format: "[group_name][sender] <message>"
            formatted_message = f"[{group_name}][{self.client.username}] {message_body}\n"

            # Send to all group members
            for member in group.members:
                if member in self.client_manager.clients:
                    try:
                        self.client_manager.send_message(member, formatted_message)
                    except:
                        print(f"Failed to send group message to {member}")
                    # Record in chat history
                    self.client_manager.add_to_history(member, formatted_message)

        elif subcommand == 'leave':
            success, msg = self.client_manager.group_manager.remove_member(
                group_name, 
                self.client.username
            )
            if success:
                self.client.send_message(f"You have left the group '{group_name}'.\n")
                # Notify other members
                group = self.client_manager.group_manager.groups[group_name]
                for member in group.members:
                    if member != self.client.username:
                        self.client_manager.send_message(
                            member, 
                            f"{self.client.username} has left the group '{group_name}'.\n"
                        )
            else:
                self.client.send_message(f"{msg}\n")

        elif subcommand == 'delete':
            success, msg = self.client_manager.group_manager.delete_group(
                group_name, 
                self.client.username
            )
            self.client.send_message(f"{msg}\n")

        else:
            self.client.send_message("Unknown @group subcommand.\n")

    def handle_file_transfer(self, tokens):
        """Handle file transfer commands"""
        if len(tokens) < 3:
            self.client.send_message("Usage: @sendfile <filename> <recipient> or @sendfile-group <filename> <group_name>\n")
            return
        
        command = tokens[0].lower()
        filename = tokens[1]
        target = tokens[2]
        
        if command == '@sendfile':
            # Single recipient file transfer
            if target not in self.client_manager.clients:
                self.client.send_message(f"User '{target}' not found.\n")
                return
                
            recipient = self.client_manager.clients[target]
            recipient.send_message(f"[FILE] {self.client.username} is sending you file '{filename}'. Type @acceptfile to accept or @rejectfile to reject.\n")
            # Store pending transfer info
            recipient.pending_file_transfer = {
                'filename': filename,
                'sender': self.client.username,
                'sender_client': self.client
            }
            
        elif command == '@sendfile-group':
            # Group file transfer
            group = self.client_manager.group_manager.groups.get(target)
            if not group:
                self.client.send_message(f"Group '{target}' does not exist.\n")
                return
                
            if not group.is_member(self.client.username):
                self.client.send_message(f"You are not a member of group '{target}'.\n")
                return
                
            for member in group.members:
                if member != self.client.username and member in self.client_manager.clients:
                    recipient = self.client_manager.clients[member]
                    recipient.send_message(f"[FILE] {self.client.username} is sending file '{filename}' to group '{target}'. Type @acceptfile to accept or @rejectfile to reject.\n")
                    # Store pending transfer info
                    recipient.pending_file_transfer = {
                        'filename': filename,
                        'sender': self.client.username,
                        'sender_client': self.client,
                        'group': target
                    }
    
    def handle_file_response(self, command):
        """Handle file transfer response (accept/reject)"""
        if not hasattr(self.client, 'pending_file_transfer'):
            self.client.send_message("No pending file transfers.\n")
            return
            
        transfer_info = self.client.pending_file_transfer
        sender_client = transfer_info['sender_client']
        filename = transfer_info['filename']
        
        if command == '@acceptfile':
            sender_client.send_message(f"{self.client.username} accepted the file transfer for '{filename}'. Starting transfer...\n")
            self.client.send_message(f"Accepting file transfer for '{filename}'...\n")
            
            # Signal start of transfer
            self.client.send_message("FILE_TRANSFER_START\n")
            
        elif command == '@rejectfile':
            sender_client.send_message(f"{self.client.username} rejected the file transfer for '{filename}'.\n")
            self.client.send_message(f"Rejected file transfer for '{filename}'.\n")
            
        delattr(self.client, 'pending_file_transfer')

    def handle_message(self, message):
        """Process incoming messages and commands"""
        tokens = message.split()
        if not tokens:
            return True

        # Handle encryption commands
        # if tokens[0].lower() in ['@encrypt', '@decrypt']:
        #     self.handle_encryption_command(tokens)
        #     return True
            
        # Handle standard commands
        if tokens[0].lower() in ['@quit', '@names', '@history', '@help']:
            return self.handle_standard_commands(tokens)
            
        # Handle group commands
        if tokens[0].lower().startswith('@group'):
            self.handle_group_command(tokens)
            return True
        
        # Handle file transfer commands
        elif tokens[0].lower() in ['@sendfile', '@sendfile-group']:
            self.handle_file_transfer(tokens)
            return True
        # Handle file transfer responses
        elif tokens[0].lower() in ['@acceptfile', '@rejectfile']:
            self.handle_file_response(tokens[0].lower())
            return True
            
        # Handle private messages
        if tokens[0].startswith('@'):
            recipient = tokens[0][1:]
            pm_body = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
            if recipient in self.client_manager.clients:
                self.client_manager.send_private(self.client.username, recipient, pm_body)
            else:
                self.client.socket.sendall(b"Reminder: Invalid command. Use @help\n")
            return True

        # Handle regular messages
        is_encrypted, content = parse_encrypted_message(message)
        if is_encrypted:
            self.client_manager.broadcast(f"[{self.client.username}] {message}\n", self.client.username)
        else:
            self.client_manager.broadcast(f"[{self.client.username}] {message}\n", self.client.username)
        return True

    def run(self):
        """Main handler loop"""
        if not self.setup_username():
            self.client.socket.close()
            return

        while True:
            try:
                data = self.client.socket.recv(1024)
                if not data:
                    break
                
                message = data.decode('utf-8').strip()
                if not message:
                    continue
                
                if not self.handle_message(message):
                    break
                    
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"Exception in client thread ({self.client.username}): {e}")
                break

        self.client.socket.close()
        if self.client.username in self.client_manager.clients:
            self.client_manager.remove_client(self.client.username)
        print(f"[-] {self.client.username} disconnected from {self.client.address}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, port))
    server_socket.listen(5)
    
    client_manager = ClientManager()
    print(f"Server started on port {port}. Waiting for connections...")

    try:
        while True:
            try:
                client_sock, addr = server_socket.accept()
                handler = ClientHandler(client_sock, addr, client_manager)
                t = threading.Thread(target=handler.run, daemon=True)
                t.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        for username, client in list(client_manager.clients.items()):
            try:
                client.send_message("Server is shutting down. Closing connection...\n")
            except:
                pass
            client.close()
        client_manager.clients.clear()
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == "__main__":
    main()