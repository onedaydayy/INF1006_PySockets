import socket
import sys
import threading
import re
from collections import defaultdict
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
        formatted_message = f"[{sender} -> {group_name}] {message}\n"

        # Send to all group members
        for member in group.members:
            client_manager.send_message(member, formatted_message)
        
        return True, "Message sent"

class Client:
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
        try:
            self.client.socket.sendall(b"Enter a unique username: ")
            username = self.client.socket.recv(1024).decode('utf-8').strip()
            
            if not username or not re.match("^[A-Za-z0-9_]+$", username):
                self.client.socket.sendall(b"Invalid username.\n")
                return False

            if not self.client_manager.add_client(username, self.client):
                self.client.socket.sendall(b"Username is already taken.\n")
                return False

            self.client.username = username
            print(f"[+] {username} connected from {self.client.address}")
            self.client_manager.broadcast(f"{username} has joined the chat.\n", username)
            self.client.send_message("Welcome to the chat!\n")
            return True

        except Exception as e:
            print(f"Error during initial username setup: {e}")
            return False

    def handle_encryption_command(self, tokens):
        """Handle @encrypt and @decrypt commands"""
        if tokens[0].lower() == '@encrypt':
            if len(tokens) < 3:
                self.client.socket.sendall(b"Usage: @encrypt password message\n")
            return

            password = tokens[1]
            msg_content = ' '.join(tokens[2:])
            
            try:
                encrypted = encrypt_message(msg_content, password)
                formatted_msg = format_encrypted_message(encrypted)
                self.client_manager.broadcast(f"[{self.client.username}] {formatted_msg}\n", self.client.username)
            except:
                self.client.socket.sendall(b"Encryption failed. Please try again.\n")
                
        elif tokens[0].lower() == '@decrypt':
            if len(tokens) < 3:
                self.client.socket.sendall(b"Usage: @decrypt password encrypted_message\n")
                return
            
            password = tokens[1]
            enc_message = ' '.join(tokens[2:])
            
            is_encrypted, enc_data = parse_encrypted_message(enc_message)
            if not is_encrypted:
                self.client.socket.sendall(b"Not a valid encrypted message.\n")
                return
            
            try:
                decrypted = decrypt_message(enc_data, password)
                if decrypted:
                    self.client.socket.sendall(f"Decrypted message: {decrypted}\n".encode('utf-8'))
                else:
                    self.client.socket.sendall(b"Failed to decrypt. Wrong password?\n")
            except:
                self.client.socket.sendall(b"Decryption failed. Invalid message format.\n")

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
                    success_add, msg_add = self.client_manager.group_manager.add_member(group_name, member)
                    if success_add:
                        # Notify the newly added member.  THIS IS THE KEY CHANGE.
                        self.client_manager.send_message(member, f"You have been added to group '{group_name}'.\n")
                    else:
                        self.client.send_message(msg_add) #notify the creator of the group

                self.client.send_message(f"Group '{group_name}' created with members: {', '.join(members)}\n")
            else:
                self.client.send_message(f"{msg}\n")

        elif subcommand == 'send':
            message_body = ' '.join(tokens[3:])
            success, msg = self.client_manager.group_manager.send_message(
                group_name, 
                self.client.username, 
                message_body, 
                self.client_manager
            )
            if not success:
                self.client.send_message(f"{msg}\n")

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

    def handle_message(self, message):
        """Process incoming messages and commands"""
        tokens = message.split()
        if not tokens:
            return True

        # Handle encryption commands
        if tokens[0].lower() in ['@encrypt', '@decrypt']:
            self.handle_encryption_command(tokens)
            return True
            
        # Handle standard commands
        if tokens[0].lower() in ['@quit', '@names', '@history', '@help']:
            return self.handle_standard_commands(tokens)
            
        # Handle group commands
        if tokens[0].lower().startswith('@group'):
            self.handle_group_command(tokens)
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