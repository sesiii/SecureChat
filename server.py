import socket
import threading
import bcrypt
import logging
import sys

# Configuration
HOST = '127.0.0.1'
PORT = 60008

# Setup Logging to both Terminal and File
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("chat_server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Shared state
clients = {} # {socket: username}
user_db = {
    "alice": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("letmein".encode(), bcrypt.gensalt()),
    "charlie": bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt()),
    "dave": bcrypt.hashpw("123456".encode(), bcrypt.gensalt())
}
clients_lock = threading.Lock()

def broadcast(message, sender_socket=None):
    """
    Sends a message to all authenticated clients except the sender.
    Logs the message to the server console and file.
    """
    logging.info(f"Broadcast: {message}")
    encoded_msg = message.encode('utf-8')
    
    with clients_lock:
        for client_socket in list(clients.keys()):
            # Logic: Only send if it's NOT the sender_socket
            if client_socket != sender_socket:
                try:
                    client_socket.sendall(encoded_msg)
                except Exception as e:
                    logging.error(f"Failed to send to a client: {e}")
                    remove_client(client_socket)

def remove_client(client_socket):
    """Cleanup client session and handle disconnects gracefully[cite: 11, 15]."""
    with clients_lock:
        user = clients.pop(client_socket, None)
        try:
            client_socket.close()
        except:
            pass
        return user

def handle_authentication(client_socket, addr):
    """Handles the LOGIN <username> <password> requirement[cite: 14]."""
    while True:
        try:
            client_socket.sendall("AUTH_REQUIRED: Please LOGIN <username> <password>".encode())
            data = client_socket.recv(1024).decode('utf-8').strip()
            
            if not data:
                return None

            parts = data.split()
            if len(parts) == 3 and parts[0].upper() == "LOGIN":
                _, username, password = parts
                
                # Securely verify credentials [cite: 14]
                if username in user_db and bcrypt.checkpw(password.encode(), user_db[username]):
                    with clients_lock:
                        # Reject Duplicate Login Policy 
                        if username in clients.values():
                            client_socket.sendall("ERROR: User already logged in.\n".encode())
                            logging.warning(f"Duplicate login attempt rejected for: {username} from {addr}")
                            continue
                        
                        clients[client_socket] = username
                    
                    client_socket.sendall(f"SUCCESS: Welcome {username}\n".encode())
                    logging.info(f"User '{username}' authenticated from {addr}")
                    return username
                else:
                    client_socket.sendall("ERROR: Invalid credentials.\n".encode())
                    logging.warning(f"Failed login attempt for '{username}' from {addr}")
            else:
                client_socket.sendall("ERROR: Use format LOGIN <username> <password>\n".encode())
        except Exception as e:
            logging.error(f"Auth error for {addr}: {e}")
            return None

def handle_client(client_socket, addr):
    """Manages the client thread using threading.Thread[cite: 9, 10]."""
    username = handle_authentication(client_socket, addr)
    
    if not username:
        remove_client(client_socket)
        return

    broadcast(f"🟢 {username} joined the chat.")

    try:
        while True:
            # Blocking I/O read [cite: 9]
            msg = client_socket.recv(1024).decode('utf-8')
            if not msg:
                break
            
            # Broadcast to everyone ELSE
            broadcast(f"{username}: {msg}", sender_socket=client_socket)
    except Exception as e:
        logging.debug(f"Connection error with {username}: {e}")
    finally:
        user = remove_client(client_socket)
        if user:
            broadcast(f"🔴 {user} left the chat.")
            logging.info(f"User '{user}' session ended.")

def start_server():
    """Initializes the TCP server using socket[cite: 10]."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    logging.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            # One thread per connected client [cite: 10]
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()