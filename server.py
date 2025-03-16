# server.py (FINAL, CORRECTED VERSION - No Logic Changes, Just Structure)
import socket
import threading
import sys
from collections import defaultdict

HOST = '0.0.0.0'

clients = {}
groups = {}
chat_history = defaultdict(list)

COMMANDS_HELP = """Available Commands:
@quit - Disconnect from the server.
@names - List all online users.
@username <message> - Send a private message.
@everyone <message> - Send a message to all users (same as not using any @ command).
@group set <group_name> <members> - Create a group.  Example: @group set mygroup user1,user2,user3
@group send <group_name> <message> - Send a message to a group.
@group leave <group_name> - Leave a group.
@group delete <group_name> - Delete a group.
@history - View chat history.
@help - Show this help message.
@encrypt on - Turn on Encryption.
@encrypt off - Turn off Encryption
"""

def broadcast(message, sender=None):
    for user, sock in clients.items():
        if user != sender:
            try:
                sock.sendall(message.encode('utf-8'))
            except:
                print(f"Failed to send message to {user}")
    if sender:
        chat_history[sender].append(message)

def send_private_message(sender, recipient, message):
    if recipient not in clients:
        clients[sender].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
        return

    full_message = f"[PM from {sender}] {message}\n"
    try:
        clients[recipient].sendall(full_message.encode('utf-8'))
        chat_history[sender].append(full_message)
        chat_history[recipient].append(full_message)
    except Exception as e:
        print(f"Failed to send private message to {recipient}: {e}")

def handle_group_set(sender, tokens):
    if len(tokens) < 4:
        clients[sender].sendall(b"No members specified for group set.\n")
        return

    group_name = tokens[2]
    member_string = ' '.join(tokens[3:])
    member_string = member_string.replace(',', ' ')
    members = member_string.split()
    members.append(sender)  # Add creator

    if group_name in groups:
        clients[sender].sendall(f"Group '{group_name}' already exists.\n".encode('utf-8'))
        return

    groups[group_name] = set(members)
    clients[sender].sendall(f"Group '{group_name}' created with members {list(groups[group_name])}.\n".encode('utf-8'))
    for member in members:
        if member in clients and member != sender:
            clients[member].sendall(f"You have been added to group '{group_name}' by {sender}.\n".encode('utf-8'))

def handle_group_send(sender, tokens):
    if len(tokens) < 4:
        clients[sender].sendall(b"Invalid @group send format.\n")
        return

    group_name = tokens[2]
    message_body = ' '.join(tokens[3:])

    if group_name not in groups:
        clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
        return
    if sender not in groups[group_name]:
        clients[sender].sendall(f"You are not a member of '{group_name}'.n".encode('utf-8'))
        return

    full_message = f"[{sender} -> {group_name}] {message_body}\n"
    for user in groups[group_name]:
        if user in clients:
            clients[user].sendall(full_message.encode('utf-8'))
            chat_history[user].append(full_message)

def handle_group_leave(sender, group_name):
    if group_name not in groups:
        clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
        return
    if sender not in groups[group_name]:
        clients[sender].sendall(f"You are not in group '{group_name}'.n".encode('utf-8'))
        return

    groups[group_name].remove(sender)
    clients[sender].sendall(f"You have left the group '{group_name}'.n".encode('utf-8'))
    for member in groups[group_name]:
        if member in clients:
            clients[member].sendall(f"{sender} has left the group '{group_name}'.n".encode('utf-8'))
    if len(groups[group_name]) == 0:
        del groups[group_name]
        broadcast(f"Group '{group_name}' has been automatically deleted because all members left.\n")

def handle_group_delete(sender, group_name):
    if group_name not in groups:
        clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
        return

    for member in list(groups[group_name]):
        if member in clients:
            clients[member].sendall(f"The group '{group_name}' has been deleted by {sender}.\n".encode('utf-8'))
    del groups[group_name]
    clients[sender].sendall(f"Group '{group_name}' has been deleted.\n".encode('utf-8'))

def handle_group_command(sender, tokens):
    if len(tokens) < 2:
        clients[sender].sendall(b"Invalid @group command format.\n")
        return

    subcommand = tokens[1].lower()
    if subcommand == 'set':
        handle_group_set(sender, tokens)
    elif subcommand == 'send':
        handle_group_send(sender, tokens)
    elif subcommand == 'leave':
        if len(tokens) < 3:
             clients[sender].sendall(b"Invalid @group leave format.\n")
             return
        handle_group_leave(sender, tokens[2])
    elif subcommand == 'delete':
        if len(tokens) < 3:
            clients[sender].sendall(b"Invalid @group delete format.\n")
            return
        handle_group_delete(sender, tokens[2])
    else:
        clients[sender].sendall(b"Unknown @group subcommand.\n")

def list_users(requester):
    names_str = ", ".join(clients.keys())
    clients[requester].sendall(f"Online users: {names_str}\n".encode('utf-8'))

def send_help(client_sock):
    client_sock.sendall(COMMANDS_HELP.encode('utf-8'))

def send_history(username, client_sock):
    history = chat_history[username]
    if history:
        formatted_history = "\n".join(history) + "\n"
        client_sock.sendall(formatted_history.encode('utf-8'))
    else:
        client_sock.sendall(b"No chat history found.\n")

def handle_client_message(username, message, client_sock):
    """Handles a single message received from a client."""
    if message.lower() == '@quit':
        return False  # Signal to close connection

    elif message.lower() == '@names':
        list_users(username)

    elif message.lower() == '@history':
        send_history(username, client_sock)

    elif message.lower() == '@help':
        send_help(client_sock)

    elif message.startswith('@salt'):
        broadcast(f"@{username} salt {message.split(' ', 1)[1]}\n")

    elif message.startswith('@'):
        tokens = message.split()
        if len(tokens) < 1:
            return True

        if tokens[0].lower().startswith('@group'):
            handle_group_command(username, tokens)

        elif tokens[0].lower() == '@everyone':
            everyone_message = ' '.join(tokens[1:])
            broadcast(f"[{username} (to everyone)] {everyone_message}\n", sender=username)

        elif tokens[0].startswith('@'):
            recipient = tokens[0][1:]
            if recipient not in clients:
                clients[username].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
            else:
                pm_body = ' '.join(tokens[1:])
                send_private_message(username, recipient, pm_body)
        else:
            clients[username].sendall(b"Unknown command.\n")
    else:
        broadcast(f"[{username}] {message}\n", sender=username)
    return True

def client_thread(client_sock, addr):
    """Handles a client connection."""
    try:
        ready_msg = client_sock.recv(1024).decode('utf-8').strip()
        if ready_msg != "CLIENT_READY":
            print("Unexpected initial message from client. Closing connection.")
            client_sock.close()
            return

        client_sock.sendall(b"Enter a unique username: \n")
        username = client_sock.recv(1024).decode('utf-8').strip()
        if not username:
            client_sock.sendall(b"Invalid username.\n")
            client_sock.close()
            return

        if username in clients:
            client_sock.sendall(b"Username is already taken. Disconnecting.\n")
            client_sock.close()
            return

        clients[username] = client_sock
        print(f"[+] {username} connected from {addr}")
        broadcast(f"{username} has joined the chat.\n", sender=username)
        client_sock.sendall(b"Welcome to the chat!\n")

        while True:
            data = client_sock.recv(1024)
            if not data:
                break

            for line in data.decode('utf-8').splitlines():
                message = line.strip()
                if message:
                    if not handle_client_message(username, message, client_sock):
                        break
            else:
                continue
            break

    except Exception as e:
        print(f"Error in client thread: {e}")
    finally:
        if client_sock:
            client_sock.close()
        if username in clients:
            del clients[username]
        for group_name in list(groups.keys()):
            if username in groups[group_name]:
                groups[group_name].remove(username)
                for member in groups[group_name]:
                    if member in clients:
                        clients[member].sendall(f"{username} has left the group '{group_name}' due to quitting.\n".encode('utf-8'))
                if len(groups[group_name]) == 0:
                    del groups[group_name]
                    broadcast(f"Group '{group_name}' has been automatically deleted because all members left.\n")
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
            client_sock, addr = server_socket.accept()
            threading.Thread(target=client_thread, args=(client_sock, addr)).start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()