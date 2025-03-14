import socket
import threading
import sys

HOST = '0.0.0.0'  # Listen on all available interfaces

# Global data structures
clients = {}        # Maps username -> client socket
groups = {}         # Maps groupName -> set of usernames

def broadcast(message, sender=None):
    """
    Send a message to every connected client (except the sender, if provided).
    """
    for user, sock in clients.items():
        if user != sender:  # skip sending back to the sender if you prefer
            try:
                sock.sendall(message.encode('utf-8'))
            except:
                print(f"Failed to send message to {user}")

def send_private(sender, recipient, msg):
    """
    Send a private message from 'sender' to 'recipient' (username).
    """
    if recipient not in clients:
        # recipient does not exist
        if sender in clients:
            clients[sender].sendall(f"User '{recipient}' not found.\n".encode('utf-8'))
        return
    try:
        clients[recipient].sendall(f"[PM from {sender}] {msg}\n".encode('utf-8'))
    except:
        print(f"Failed to send private message to {recipient}")

def handle_group_command(sender, tokens):
    """
    Handle commands starting with '@group' followed by 'set', 'send', 'leave', 'delete', etc.
    Syntax examples:
      @group set myGroup user1, user2
      @group send myGroup Hello group
      @group leave myGroup
      @group delete myGroup
    """
    if len(tokens) < 3:
        clients[sender].sendall(b"Invalid @group command format.\n")
        return

    subcommand = tokens[1].lower()
    group_name = tokens[2]

    if subcommand == 'set':
        # @group set <groupName> user1, user2, ...
        # If no members specified after group name, just create an empty set or
        # add only the sender by default
        if len(tokens) < 4:
            clients[sender].sendall(b"No members specified for group set.\n")
            return
        # parse the members from tokens[3] which might be "user1," "user2," ...
        member_string = ' '.join(tokens[3:])  # user1, user2, ...
        member_string = member_string.replace(',', ' ')
        members = member_string.split()
        # optionally add the sender if you want them in the group by default
        members.append(sender)

        if group_name in groups:
            clients[sender].sendall(f"Group '{group_name}' already exists.\n".encode('utf-8'))
            return
        groups[group_name] = set(members)
        clients[sender].sendall(f"Group '{group_name}' created with members {members}\n".encode('utf-8'))

    elif subcommand == 'send':
        # @group send <groupName> <message>
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        if sender not in groups[group_name]:
            clients[sender].sendall(f"You are not a member of '{group_name}'.\n".encode('utf-8'))
            return
        # The message is everything after '@group send groupName'
        # tokens: ['@group','send','myGroup','Hello','there']
        message_body = ' '.join(tokens[3:])
        # broadcast to group members
        for user in groups[group_name]:
            if user in clients and user != sender:
                clients[user].sendall(f"[{sender} -> {group_name}] {message_body}\n".encode('utf-8'))

    elif subcommand == 'leave':
        # @group leave <groupName>
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        if sender not in groups[group_name]:
            clients[sender].sendall(f"You are not in group '{group_name}'.\n".encode('utf-8'))
            return
        groups[group_name].remove(sender)
        clients[sender].sendall(f"You have left the group '{group_name}'.\n".encode('utf-8'))

    elif subcommand == 'delete':
        # @group delete <groupName>
        if group_name not in groups:
            clients[sender].sendall(f"Group '{group_name}' does not exist.\n".encode('utf-8'))
            return
        # You might optionally check if the sender is allowed to delete
        # For now, let the user who created it or any user do it
        del groups[group_name]
        clients[sender].sendall(f"Group '{group_name}' has been deleted.\n".encode('utf-8'))

    else:
        clients[sender].sendall(b"Unknown @group subcommand.\n")

def list_users(requester):
    """
    Sends the list of all connected usernames to the 'requester' client.
    """
    names_str = ", ".join(clients.keys())
    clients[requester].sendall(f"Online users: {names_str}\n".encode('utf-8'))

def client_thread(client_sock, addr):
    """
    Thread that handles an individual client's connection.
    """
    # 1) Prompt for username
    try:
        client_sock.sendall(b"Enter a unique username: ")
        username = client_sock.recv(1024).decode('utf-8').strip()
        if not username:
            client_sock.sendall(b"Invalid username.\n")
            client_sock.close()
            return
        
        # 2) Check duplicates
        if username in clients:
            client_sock.sendall(b"Username is already taken. Disconnecting.\n")
            client_sock.close()
            return
        
        # Register the client
        clients[username] = client_sock
        print(f"[+] {username} connected from {addr}")
        broadcast(f"{username} has joined the chat.\n", sender=username)

        client_sock.sendall(b"Welcome to the chat!\n")
    except:
        client_sock.close()
        return

    # 3) Main loop for receiving commands/messages
    while True:
        try:
            data = client_sock.recv(1024)
            if not data:
                # Client disconnected
                break
            message = data.decode('utf-8').strip()
            if not message:
                continue

            # Check for special commands
            if message == '@quit':
                # user wants to exit
                broadcast(f"{username} has left the chat.\n", sender=username)
                break
            
            elif message == '@names':
                list_users(username)
            
            elif message.startswith('@'):
                # parse further
                tokens = message.split()
                if len(tokens) < 1:
                    continue
                # check if it's private message: @username ...
                # but also check if it's @group ...
                if tokens[0].startswith('@group'):
                    handle_group_command(username, tokens)
                else:
                    # private message
                    # example: "@Bob Hello Bob!"
                    # tokens[0] = "@Bob"
                    # tokens[1..] = message
                    recipient = tokens[0][1:]  # remove '@'
                    pm_body = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
                    send_private(username, recipient, pm_body)
            else:
                # normal broadcast
                broadcast(f"[{username}] {message}\n", sender=username)
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Exception in client thread: {e}")
            break
    
    # Cleanup: user left or error
    client_sock.close()
    if username in clients:
        del clients[username]
    print(f"[-] {username} disconnected from {addr}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <5000>")
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
            t = threading.Thread(target=client_thread, args=(client_sock, addr))
            t.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
