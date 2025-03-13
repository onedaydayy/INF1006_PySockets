import socket
import threading
import openai
import os

# ===========================
# Configuration
# ===========================
HOST = '0.0.0.0'    # Listen on all interfaces
PORT = 12345       # Arbitrary port for the server
openai.api_key = os.environ.get("OPENAI_API_KEY")  # Must be set in your environment

# ===========================
# Global Data Structures
# ===========================
clients_lock = threading.Lock()
clients = {}   # username -> (socket, address)

groups_lock = threading.Lock()
groups = {}    # group_name -> set of usernames

# ===========================
# Helper Functions
# ===========================
def broadcast_message(msg, exclude_user=None):
    """
    Sends a message to all connected clients except possibly one user.
    """
    with clients_lock:
        for user, (sock, _) in clients.items():
            if user != exclude_user:
                send_message(sock, msg)

def send_message(sock, msg):
    """
    Sends a string message to a specific client's socket.
    """
    try:
        sock.sendall(msg.encode('utf-8'))
    except BrokenPipeError:
        # Handle case if client is disconnected mid-send
        pass

def rephrase_text_via_openai(text):
    """
    Calls the OpenAI API to rephrase the provided text.
    Returns the rephrased version as a string, or an error message on failure.
    """
    if not openai.api_key:
        return "OpenAI API key not configured on server. Cannot rephrase."

    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=f"Rephrase the following sentence with similar meaning:\n\n{text}\n\nRephrased:",
            max_tokens=100,
            temperature=0.7
        )
        # Extract text
        rephrased = response.choices[0].text.strip()
        return rephrased
    except Exception as e:
        return f"Error calling OpenAI API: {e}"

def handle_group_set(requester, group_name, members_str):
    """
    Creates a new group or updates an existing group with given members.
    Format: @group set group_name user1, user2, ...
    """
    new_members = [m.strip() for m in members_str.split(',') if m.strip()]
    new_members.append(requester)  # ensure the creator is also in the group

    with groups_lock:
        if group_name in groups:
            send_message(clients[requester][0],
                         f"[Server] Group '{group_name}' already exists.\n")
            return

        groups[group_name] = set(new_members)

    # Notify everyone in the group
    for m in new_members:
        if m in clients:
            send_message(clients[m][0],
                         f"[Server] You have been added to group '{group_name}'.\n")
    send_message(clients[requester][0],
                 f"[Server] Group '{group_name}' created with members: {', '.join(new_members)}\n")

def handle_group_send(requester, group_name, message):
    """
    Sends a message to all members of the specified group.
    """
    with groups_lock:
        if group_name not in groups:
            send_message(clients[requester][0],
                         f"[Server] Group '{group_name}' does not exist.\n")
            return
        if requester not in groups[group_name]:
            send_message(clients[requester][0],
                         f"[Server] You are not in group '{group_name}'.\n")
            return

        # Forward message to all group members
        for member in groups[group_name]:
            if member in clients:  # If they're online
                send_message(clients[member][0],
                             f"[Group:{group_name}] {requester}: {message}\n")

def handle_group_leave(requester, group_name):
    """
    Removes the requester from the specified group.
    """
    with groups_lock:
        if group_name not in groups:
            send_message(clients[requester][0],
                         f"[Server] Group '{group_name}' does not exist.\n")
            return
        if requester not in groups[group_name]:
            send_message(clients[requester][0],
                         f"[Server] You are not in group '{group_name}'.\n")
            return

        groups[group_name].remove(requester)
        send_message(clients[requester][0],
                     f"[Server] You have left group '{group_name}'.\n")

def handle_group_delete(requester, group_name):
    """
    Deletes the group. (You may add ownership checks if desired.)
    """
    with groups_lock:
        if group_name not in groups:
            send_message(clients[requester][0],
                         f"[Server] Group '{group_name}' does not exist.\n")
            return
        # If you want to enforce "only creator can delete," track the creator
        # or allow any member:
        if requester not in groups[group_name]:
            send_message(clients[requester][0],
                         f"[Server] You are not a member of '{group_name}'.\n")
            return

        # Notify members of deletion
        members = groups[group_name]
        for m in members:
            if m in clients:
                send_message(clients[m][0],
                             f"[Server] Group '{group_name}' has been deleted.\n")
        del groups[group_name]

def handle_client_messages(client_socket, address):
    """
    Main loop to handle commands/messages from a single client.
    """
    username = None
    try:
        # First, get a unique username
        while True:
            client_socket.sendall("Enter your desired username: ".encode('utf-8'))
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data:
                # Connection closed or empty
                client_socket.close()
                return

            candidate = data
            with clients_lock:
                if candidate not in clients:
                    # Accept
                    username = candidate
                    clients[username] = (client_socket, address)
                    break
                else:
                    client_socket.sendall("[Server] Username already taken.\n".encode('utf-8'))

        # Broadcast that this user joined
        broadcast_message(f"[Server] {username} has joined the chat.\n")

        # Now handle further commands
        while True:
            msg = client_socket.recv(1024)
            if not msg:
                # Client disconnected abruptly
                break

            msg_decoded = msg.decode('utf-8').strip()

            # Check for commands
            if msg_decoded.startswith('@quit'):
                # User wants to disconnect
                broadcast_message(f"[Server] {username} has disconnected.\n", exclude_user=username)
                break

            elif msg_decoded.startswith('@names'):
                # List all connected users
                with clients_lock:
                    current_users = ", ".join(clients.keys())
                send_message(client_socket, f"[Server] Connected users: {current_users}\n")

            elif msg_decoded.startswith('@rephrase '):
                # Rephrase command
                original_text = msg_decoded[len('@rephrase '):].strip()
                rephrased = rephrase_text_via_openai(original_text)
                send_message(client_socket, f"[Rephrased] {rephrased}\n")

            elif msg_decoded.startswith('@group '):
                # Group-related commands: set, send, leave, delete
                # e.g., "@group set groupName user1, user2"
                #       "@group send groupName message"
                #       "@group leave groupName"
                #       "@group delete groupName"
                parts = msg_decoded.split(' ', 2)  # split into ["@group", "set", "groupName user1,..."]
                if len(parts) < 3:
                    send_message(client_socket, "[Server] Invalid @group command.\n")
                    continue

                sub_command = parts[1]  # "set", "send", "leave", or "delete"
                remainder = parts[2].strip()

                if sub_command == 'set':
                    # remainder is "groupName user1, user2"
                    # Need to further parse out groupName
                    # Let's assume 'groupName' is the first token, then the rest is members
                    sub_parts = remainder.split(' ', 1)
                    if len(sub_parts) < 2:
                        send_message(client_socket, "[Server] Usage: @group set <group> <members>\n")
                        continue
                    group_name = sub_parts[0].strip()
                    members_str = sub_parts[1].strip()
                    handle_group_set(username, group_name, members_str)

                elif sub_command == 'send':
                    # remainder is "groupName message"
                    sub_parts = remainder.split(' ', 1)
                    if len(sub_parts) < 2:
                        send_message(client_socket, "[Server] Usage: @group send <group> <message>\n")
                        continue
                    group_name = sub_parts[0].strip()
                    group_message = sub_parts[1].strip()
                    handle_group_send(username, group_name, group_message)

                elif sub_command == 'leave':
                    group_name = remainder.strip()
                    handle_group_leave(username, group_name)

                elif sub_command == 'delete':
                    group_name = remainder.strip()
                    handle_group_delete(username, group_name)
                else:
                    send_message(client_socket, "[Server] Unknown group command.\n")

            elif msg_decoded.startswith('@'):
                # Possibly a private message, e.g. "@bob Hello there"
                # Parse out the user and the message
                # The pattern is "@username message"
                parts = msg_decoded.split(' ', 1)
                if len(parts) < 2:
                    send_message(client_socket, "[Server] Invalid command.\n")
                    continue
                target = parts[0][1:]  # remove '@'
                private_msg = parts[1]
                with clients_lock:
                    if target in clients:
                        send_message(clients[target][0],
                                     f"[Private] {username}: {private_msg}\n")
                    else:
                        send_message(client_socket,
                                     f"[Server] User '{target}' not found.\n")

            else:
                # Broadcast to everyone
                broadcast_message(f"{username}: {msg_decoded}\n")

    except ConnectionError:
        # In case of a sudden disconnect
        pass
    finally:
        # Cleanup on exit
        if username:
            with clients_lock:
                if username in clients:
                    del clients[username]
        broadcast_message(f"[Server] {username} has disconnected.\n", exclude_user=username)
        client_socket.close()

def start_server():
    """
    Main server start function.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server started on {HOST}:{PORT}...")

    try:
        while True:
            client_sock, addr = server_socket.accept()
            # Launch a thread to handle this client
            handler_thread = threading.Thread(target=handle_client_messages,
                                              args=(client_sock, addr),
                                              daemon=True)
            handler_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
