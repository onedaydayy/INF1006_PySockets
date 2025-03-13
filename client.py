import socket
import threading
import sys

# Adjust these as needed to match your server settings
HOST = '127.0.0.1'
PORT = 12345

def receive_messages(sock):
    """
    Continuously listens for messages from the server and prints them.
    """
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("[Server] Connection closed.")
                break
            print(data.decode('utf-8'), end='')  # end='' because data may already have a newline
        except ConnectionError:
            print("[Error] Lost connection to the server.")
            break
    # Once the loop ends, close the socket and exit
    sock.close()
    sys.exit()

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[Error] Cannot connect to server. Is it running?")
        return

    # Start a thread to listen for incoming messages
    listener_thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
    listener_thread.start()

    # Main loop: read user input and send to server
    while True:
        try:
            message = input()
            # If the user typed nothing, just continue
            if not message.strip():
                continue

            client_socket.sendall(message.encode('utf-8'))

            # If user typed "@quit", we close and exit
            if message.startswith('@quit'):
                print("[Info] Disconnecting from the server...")
                break
        except (EOFError, KeyboardInterrupt):
            print("[Info] Disconnecting from the server...")
            client_socket.sendall("@quit".encode('utf-8'))
            break
        except BrokenPipeError:
            print("[Error] Lost connection to the server.")
            break

    client_socket.close()
    sys.exit()

if __name__ == "__main__":
    main()
