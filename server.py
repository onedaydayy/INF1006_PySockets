import socket
import threading
import sys
from collections import defaultdict

HOST = '0.0.0.0'

clients = {}
groups = {}
# Dictionary to store chat history: username -> list of messages
chat_history = defaultdict(list)

def broadcast(message, sender=None):
    """
    Send a message to every connected client (except the sender, if provided).
    """
    for user, sock in clients.items():
        if user != sender:
            try:
                sock.sendall(message.encode('utf-8'))
            except:
                print(f"Failed to send message to {user}")
    if sender:
        chat_history[sender].append(message) # store in the history.

def send_private(sender, recipient, msg):
    """
    Send a private message.
    """
    if recipient not in clients:
        if sender in clients:
             clients[sender].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
        return

    try:
        full_message = f"[PM from {sender}] {msg}\n"
        clients[recipient].sendall(full_message.encode('utf-8'))
        # store the message in history for both sender and receiver.
        chat_history[sender].append(full_message)
        chat_history[recipient].append(full_message)

    except:
        print(f"Failed to send private message to {recipient}")

def handle_group_command(sender, tokens):
    """Handles @group commands."""
    if len(tokens) < 3:
        clients[sender].sendall(b"Invalid @group command format.\n")
        return

    subcommand = tokens[1].lower()
    group_name = tokens[2]

    if subcommand == 'set':
        if len(tokens) < 4:
            clients[sender].sendall(b"No members specified for group set.\n")
            return
        member_string = ' '.join(tokens[3:])
        member_string = member_string.replace(',', ' ')
        members = member_string.split()
        members.append(sender)  # Add the creator to the group

        if group_name in groups:
            clients[sender].sendall(f"Group '{group_name}' already exists.\n".encode('utf-8'))
            return
        groups[group_name] = set(members)
        clients[sender].sendall(f"Group '{group_name}' created with members {members}\n".encode('utf-8'))

    elif subcommand == 'send':
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        if sender not in groups[group_name]:
            clients[sender].sendall(f"You are not a member of '{group_name}'.n".encode('utf-8'))
            return
        message_body = ' '.join(tokens[3:])
        full_message = f"[{sender} -> {group_name}] {message_body}\n"
        for user in groups[group_name]:
            if user in clients and user != sender:  # Don't send back to sender
                clients[user].sendall(full_message.encode('utf-8'))
            if user in clients:
                chat_history[user].append(full_message) # store history.

    elif subcommand == 'leave':
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        if sender not in groups[group_name]:
            clients[sender].sendall(f"You are not in group '{group_name}'.n".encode('utf-8'))
            return
        groups[group_name].remove(sender)
        clients[sender].sendall(f"You have left the group '{group_name}'.n".encode('utf-8'))
        if len(groups[group_name]) == 0:
             del groups[group_name]


    elif subcommand == 'delete':
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        del groups[group_name]
        clients[sender].sendall(f"Group '{group_name}' has been deleted.\n".encode('utf-8'))

    else:
        clients[sender].sendall(b"Unknown @group subcommand.\n")

def list_users(requester):
    """Sends the list of connected usernames."""
    names_str = ", ".join(clients.keys())
    clients[requester].sendall(f"Online users: {names_str}\n".encode('utf-8'))

def client_thread(client_sock, addr):
    """Handles a client connection."""
    try:
        # --- Wait for the "ready" message ---
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
    except Exception as e: # catch the Exception
        print(f"Error in initial handshake: {e}")
        client_sock.close()
        return

    while True:
        try:
            data = client_sock.recv(1024)
            if not data:
                break
            message = data.decode('utf-8').strip()
            if not message:
                continue

            if message == '@quit':
                broadcast(f"{username} has left the chat.\n", sender=username)
                break
            elif message == '@names':
                list_users(username)
            elif message == '@history': # command
                # Retrieve and send chat history to client
                history = chat_history[username]
                if history:
                  for msg in history:
                    client_sock.sendall(msg.encode('utf-8'))
                else:
                  client_sock.sendall(b"No chat history found.\n")


            elif message.startswith('@salt'):
                broadcast(f"@{username} salt {message.split(' ', 1)[1]}\n") # Broadcast with username

            elif message.startswith('@'):
                tokens = message.split()
                if len(tokens) < 1:
                    continue
                if tokens[0].startswith('@group'):
                    handle_group_command(username, tokens)
                else:
                    recipient = tokens[0][1:]
                    pm_body = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
                    send_private(username, recipient, pm_body)
            else:
                broadcast(f"[{username}] {message}\n", sender=username)
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Exception in client thread: {e}")
            break

    client_sock.close()
    if username in clients:
        del clients[username]
    for group_name in list(groups.keys()):
        if username in groups[group_name]:
            groups[group_name].remove(username)
            if len(groups[group_name]) == 0:
                del groups[group_name]
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