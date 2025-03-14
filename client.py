import socket
import sys
import threading

def receive_messages(sock):
    """
    Continuously listen for server messages and print them.
    Runs on a separate thread.
    """
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                # Connection closed by server
                print("Disconnected from server.")
                break
            print(data.decode('utf-8'), end='')
        except:
            print("\nConnection lost.")
            break
    sock.close()
    sys.exit(0)

def main():
    if len(sys.argv) < 3:
        print("Usage: python client.py <server_host> <port>")
        sys.exit(1)

    server_host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_host, port))
    except Exception as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    # Start a thread to continuously read messages from the server
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    # Now read input from the user and send to server
    try:
        while True:
            user_input = input('')
            if not user_input:
                continue
            sock.sendall(user_input.encode('utf-8'))
            # If user typed '@quit', we can optionally break here
            if user_input.strip() == '@quit':
                print("You have quit the chat.")
                break
    except KeyboardInterrupt:
        print("Closing client...")

    sock.close()

if __name__ == "__main__":
    main()
