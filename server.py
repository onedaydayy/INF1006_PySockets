# server.py (Encryption Handling Added)
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

def send_private(sender, recipient, msg):
    if recipient not in clients:
        if sender in clients:
             clients[sender].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
        return

    try:
        full_message = f"[PM from {sender}] {msg}\n"
        clients[recipient].sendall(full_message.encode('utf-8'))
        chat_history[sender].append(full_message)
        chat_history[recipient].append(full_message)

    except:
        print(f"Failed to send private message to {recipient}")

def handle_group_command(sender, tokens):
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
        members.append(sender)

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
            if user in clients and user != sender:
                clients[user].sendall(full_message.encode('utf-8'))
            if user in clients:
                chat_history[user].append(full_message)

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
    names_str = ", ".join(clients.keys())
    clients[requester].sendall(f"Online users: {names_str}\n".encode('utf-8'))

def client_thread(client_sock, addr):
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
    except Exception as e:
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

            if message.lower() == '@quit':
                broadcast(f"{username} has left the chat.\n", sender=username)
                break
            elif message.lower() == '@names':
                list_users(username)
            elif message.lower() == '@history':
                history = chat_history[username]
                if history:
                    formatted_history = "\n".join(history) + "\n"
                    client_sock.sendall(formatted_history.encode('utf-8'))
                else:
                    client_sock.sendall(b"No chat history found.\n")
            elif message.lower() == '@help':
                client_sock.sendall(COMMANDS_HELP.encode('utf-8'))
            # --- Salt Handling (Broadcast) ---
            elif message.startswith('@salt'):
                # Broadcast the salt *with the username*
                broadcast(f"@{username} salt {message.split(' ', 1)[1]}\n")  # Include username
            elif message.startswith('@'):
                tokens = message.split()
                if len(tokens) < 1:
                    continue
                if tokens[0].lower().startswith('@group'):
                     handle_group_command(username, tokens)
                elif tokens[0].lower() == '@everyone':
                    everyone_message = ' '.join(tokens[1:])
                    broadcast(f"[{username} (to everyone)] {everyone_message}\n", sender=username)
                # --- Private Message (Forward Encrypted Data) ---
                elif tokens[0].startswith('@'):
                    recipient = tokens[0][1:]
                    # Check if the recipient exists
                    if recipient not in clients:
                        if username in clients:
                            clients[username].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
                        continue

                    # reconstruct the pm.
                    pm_body = data.decode('utf-8', errors='ignore').split(' ', 1)[1]
                    full_message = f"[PM from {username}] {pm_body}\n" # add username

                    try:
                        clients[recipient].sendall(full_message.encode('utf-8', errors='ignore')) # send
                        # store history for sender and receiver
                        chat_history[username].append(full_message)
                        chat_history[recipient].append(full_message)
                    except Exception as e:
                        print("Failed in sending Encrypted message", e)

                else:
                    clients[username].sendall(b"Unknown command.\n")

            # --- Broadcast (Forward Encrypted Data) ---
            else:
                 broadcast(f"[{username}] {message}\n", sender=username) # username

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