import socket
import sys
import threading
import re
from collections import defaultdict

HOST = '0.0.0.0'  # Listen on all available interfaces

# Global data structures
clients = {}         # Maps username -> client socket
groups = {}          # Maps groupName -> set of usernames
chat_history = defaultdict(list)  # Maps username -> list of messages

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
"""

def broadcast(message, sender=None):
    """
    Send a message to every connected client (except the sender).
    Also stores the message in sender's chat history.
    """
    for user, sock in list(clients.items()):
        if user != sender:
            try:
                sock.sendall(message.encode('utf-8'))
            except:
                print(f"Failed to send message to {user}")

    # Store in history (only if we actually have a sender)
    if sender:
        chat_history[sender].append(message)


def send_private(sender, recipient, msg):
    """
    Send a private message (and store it in both sender's and recipient's chat history).
    """
    if recipient not in clients:
        # If user doesn't exist, let the sender know
        if sender in clients:
            clients[sender].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
        return

    try:
        full_message = f"[PM from {sender}] {msg}\n"
        clients[recipient].sendall(full_message.encode('utf-8'))
        # Store in both users' histories
        chat_history[sender].append(full_message)
        chat_history[recipient].append(full_message)
    except:
        print(f"Failed to send private message to {recipient}")


def handle_group_command(sender, tokens_original):
    """
    Handle commands starting with '@group' followed by
    'set', 'send', 'leave', 'delete', etc.

    Syntax examples:
        @group set myGroup user1, user2
        @group send myGroup Hello group
        @group leave myGroup
        @group delete myGroup
    """
    tokens_lower = [t.lower() for t in tokens_original]
    if len(tokens_lower) < 3:
        clients[sender].sendall(b"Invalid @group command format.\n")
        return

    subcommand = tokens_lower[1]
    group_name = tokens_original[2]

    if subcommand == 'set':
        # @group set <groupName> user1, user2, ...
        if len(tokens_original) < 4:
            clients[sender].sendall(b"No members specified for group set.\n")
            return
        member_string = ' '.join(tokens_original[3:])
        member_string = member_string.replace(',', ' ')
        members = member_string.split()
        # Ensure the creator is in the group
        if sender not in members:
            members.append(sender)

        # Check if group already exists
        if group_name in groups:
            clients[sender].sendall(f"Group '{group_name}' already exists.\n".encode('utf-8'))
            return

        groups[group_name] = set(members)
        clients[sender].sendall(
            f"Group '{group_name}' created with members: {', '.join(members)}\n".encode('utf-8')
        )

    elif subcommand == 'send':
        # @group send <groupName> <message>
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        if sender not in groups[group_name]:
            clients[sender].sendall(
                f"You are not a member of '{group_name}'.\n".encode('utf-8')
            )
            return

        message_body = ' '.join(tokens_original[3:])
        full_message = f"[{sender} -> {group_name}] {message_body}\n"

        # Send to all group members
        for user in groups[group_name]:
            if user in clients:
                try:
                    clients[user].sendall(full_message.encode('utf-8'))
                except:
                    print(f"Failed to send group message to {user}")
                # Record in each member's chat history
                chat_history[user].append(full_message)

    elif subcommand == 'leave':
        # @group leave <groupName>
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        if sender not in groups[group_name]:
            clients[sender].sendall(
                f"You are not in group '{group_name}'.\n".encode('utf-8')
            )
            return

        groups[group_name].remove(sender)
        clients[sender].sendall(
            f"You have left the group '{group_name}'.\n".encode('utf-8')
        )

    elif subcommand == 'delete':
        # @group delete <groupName>
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return

        # Delete the group altogether
        del groups[group_name]
        clients[sender].sendall(
            f"Group '{group_name}' has been deleted.\n".encode('utf-8')
        )

    else:
        clients[sender].sendall(b"Unknown @group subcommand.\n")


def list_users(requester):
    """
    Sends the list of all connected usernames to the requester.
    """
    names_str = ", ".join(clients.keys())
    clients[requester].sendall(f"Online users: {names_str}\n".encode('utf-8'))


def client_thread(client_sock, addr):
    """
    Thread that handles an individual client's connection.
    """
    try:
        # Prompt for username
        client_sock.sendall(b"Enter a unique username: ")
        username = client_sock.recv(1024).decode('utf-8').strip()
        if not username:
            client_sock.sendall(b"Invalid username.\n")
            client_sock.close()
            return

        # Validate username: letters, digits, underscores only
        pattern = re.compile("^[A-Za-z0-9_]+$")
        if not pattern.match(username):
            client_sock.sendall(b"Invalid username. Only letters, numbers, and underscores allowed.\n")
            client_sock.close()
            return

        # Check for duplicates
        if username in clients:
            client_sock.sendall(b"Username is already taken. Disconnecting.\n")
            client_sock.close()
            return

        # Register the new user
        clients[username] = client_sock
        print(f"[+] {username} connected from {addr}")
        broadcast(f"{username} has joined the chat.\n", sender=username)
        client_sock.sendall(b"Welcome to the chat!\n")

    except Exception as e:
        print(f"Error during initial username setup: {e}")
        client_sock.close()
        return
    while True:
        try:
            data = client_sock.recv(1024)
            if not data:
                # Socket closed => user disconnected
                break
            message = data.decode('utf-8').strip()
            if not message:
                continue
            tokens_original = message.split()
            tokens_lower = message.lower().split()
            if not tokens_lower:
                continue
            # Check for special commands (case-insensitive)
            if tokens_lower[0] == '@quit':
                # Graceful quit
                broadcast(f"{username} has left the chat.\n", sender=username)
                break
            elif tokens_lower[0] == '@names':
                list_users(username)
            elif tokens_lower[0] == '@history':
                # Retrieve and send chat history
                history = chat_history[username]
                if history:
                    for msg in history:
                        client_sock.sendall(msg.encode('utf-8'))
                else:
                    client_sock.sendall(b"No chat history found.\n")
            elif tokens_lower[0] == '@help':
                # Send the help message to the client
                client_sock.sendall(COMMANDS_HELP.encode('utf-8'))
            elif tokens_lower[0].startswith('@group'):
                handle_group_command(username, tokens_original)
            elif tokens_lower[0].startswith('@'):
                # Handle private message or unknown command
                recipient = tokens_original[0][1:]
                pm_body = ' '.join(tokens_original[1:]) if len(tokens_original) > 1 else ''
                if recipient in clients:
                    send_private(username, recipient, pm_body)
                else:
                    client_sock.sendall(b"Invalid command. Use @help\n")
            else:
                broadcast(f"[{username}] {message}\n", sender=username)
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Exception in client thread ({username}): {e}")
            break
    client_sock.close()
    if username in clients:
        del clients[username]
    print(f"[-] {username} disconnected from {addr}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, port))
    server_socket.listen(5)
    print(f"Server started on port {port}. Waiting for connections...")

    try:
        while True:
            try:
                client_sock, addr = server_socket.accept()
                t = threading.Thread(target=client_thread, args=(client_sock, addr), daemon=True)
                t.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        # Gracefully notify all connected clients
        for user, sock in list(clients.items()):
            try:
                sock.sendall(b"Server is shutting down. Closing connection...\n")
            except:
                pass
            sock.close()
        clients.clear()
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == "__main__":
    main()
