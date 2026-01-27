import socket
import threading

# Configuration
HOST = '127.0.0.1'
PORT = 60008

# Shared state: dictionary to store client sockets and their addresses
clients = {}
clients_lock = threading.Lock()

def broadcast(message, sender_socket=None):
    """Sends a message to all connected clients except the sender."""
    with clients_lock:
        for client_socket in list(clients.keys()):
            try:
                client_socket.sendall(message.encode('utf-8'))
            except Exception:
                # Handle broken connections during broadcast
                remove_client(client_socket)

def remove_client(client_socket):
    """Removes client from the shared dictionary and closes the socket."""
    with clients_lock:
        if client_socket in clients:
            username = clients[client_socket]
            del clients[client_socket]
            client_socket.close()
            return username
    return None

def handle_client(client_socket, addr):
    """Handles the lifecycle of a single client connection."""
    print(f"[NEW CONNECTION] {addr} connected.")
    
    try:
        # For Problem 1, we use the first message as a simple username
        client_socket.sendall("Enter your username: ".encode('utf-8'))
        username = client_socket.recv(1024).decode('utf-8').strip()
        
        with clients_lock:
            clients[client_socket] = username
        
        broadcast(f"🟢 {username} has joined the chat.")

        while True:
            # Blocking I/O: This thread waits here for data
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            
            formatted_msg = f"{username}: {message}"
            print(f"[{addr}] {formatted_msg}")
            broadcast(formatted_msg)

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        user = remove_client(client_socket)
        if user:
            broadcast(f"🔴 {user} has left the chat.")
        print(f"[DISCONNECTED] {addr} disconnected.")

def start_server():
    """Initializes the TCP server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            # Start a new thread for each connection
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True # Ensures thread dies when main process exits
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    except KeyboardInterrupt:
        print("\n[SHUTTING DOWN] Server stopping...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()