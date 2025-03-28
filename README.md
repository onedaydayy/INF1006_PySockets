# Socket Programming: Developing a Chat Application Using Python and AI-Assisted Development

# Python Chat Application

This is a Python-based chat application that uses sockets for server-client communication. It supports multiple features such as broadcast messaging, private messaging, group messaging, chat history, user authentication, optional encryption, and more—all via a command-line interface.

## Group Members:
1. LUCAS LEE JING YI, 2401107, 2401107@sit.singaporetech.edu.sg
2. KIERAN SIM, 2403348, 2403348@sit.singaporetech.edu.sg
3. LIM TZE KAI, 2401009, 2401009@sit.singaporetech.edu.sg
4. ANG JING YI CLAIRER, 2402610, 2402610@sit.singaporetech.edu.sg
5. SHEILA LIM YANN TSERN, 2401392, 2401392@sit.singaporetech.edu.sg
6. JOHN AARON MENDOZA BRANZUELA, 2401762, 2401762@sit.singaporetech.edu.sg

## Features

- **Client-Server Model:**  
  Uses Python sockets and threads to handle multiple clients concurrently.

- **User Authentication:**  
  Clients are prompted for a unique username upon connection.  
  - **Username Validation:** Only letters, numbers, and underscores are allowed.  
  - **Duplicate Username Rejection:** Duplicate usernames are not permitted.

- **Messaging:**  
  - **Broadcast Messaging:**  
    Any message sent without a leading `@` is broadcast to all users.  
  - **Private Messaging:**  
    Use `@username <message>` to send a private message to a specific user.  
    *Example: `@Alice Hello, how are you?`*  
  - **Group Messaging:**  
    Manage groups with the following commands:
    - `@group set <group_name> <members>` – Create a group.
    - `@group send <group_name> <message>` – Send a message to a group.
    - `@group leave <group_name>` – Leave a group.
    - `@group delete <group_name>` – Delete a group.
    - `@group add <group_name> <members>` – Add users to a group.
    - `@group encrypt <group_name>` – Encrypt a group message in a group.
  - **List Online Users:**  
    Type `@names` to view all connected users.
  - **Chat History:**  
    Use `@history` to view your message history.
  - **Help:**  
    Type `@help` to see a list of available commands.

- **Encryption Support:**  
  Clients can enable end-to-end encryption with `@encrypt on` and disable it with `@encrypt off`. Salts are shared to allow key derivation.  
  - `@encrypt on` – Starts an encryption session  
  - `@encrypt user <username>` – Encrypts a message for a specific user  
  - `@encrypt off` – Stops the encryption session

- **File Transfer:**  
  - `@sendfile <filename> <recipient>` – Send a file to a specific user.  
  - `@acceptfile` – Accept a pending file transfer.  
  - `@rejectfile` – Reject a pending file transfer.  
  - `@viewfile <filename>` – View contents of a text file (if it exists in your folder or downloads).  

- **Graceful Shutdown:**  
  The server handles controlled shutdowns (via `KeyboardInterrupt`) by notifying all connected clients before closing connections.

- **Case-Insensitive Commands:**  
  Commands are processed without case sensitivity (e.g., `@QUIT` and `@quit` are equivalent).

- **Standardized Invalid Command Handling:**  
  Unrecognized commands return:  
  `"Invalid command. Use @help"`

## Getting Started
  - python server.py 5000
  - python client.py localhost 5000

### Prerequisites

- **Python 3.6+**
- [cryptography](https://cryptography.io/) library for encryption support.

Install the required package with:

```bash
pip install cryptography
