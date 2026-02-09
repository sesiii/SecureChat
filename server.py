import socket
import threading
import bcrypt
import logging
import sys

# Configuration
HOST = '127.0.0.1'
PORT = 60008

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("chat_server.log"), logging.StreamHandler(sys.stdout)]
)

# Shared state
clients = {}          # {socket: username} [cite: 67]
client_rooms = {}      # {socket: room_name} [cite: 79]
# New for Problem 5: {publisher_username: set(subscriber_sockets)}
subscriptions = {}     # 

user_db = {
    "alice": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("letmein".encode(), bcrypt.gensalt()),
    "charlie": bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt()),
    "dave": bcrypt.hashpw("123456".encode(), bcrypt.gensalt())
}
clients_lock = threading.Lock() # Ensures thread-safety 

def multicast_to_subscribers(message, publisher_username):
    """Multicasts the message only to its subscribers."""
    logging.info(f"PUB: {publisher_username} -> {message}")
    encoded_msg = f"[(Sub) {publisher_username}]: {message}".encode('utf-8')
    
    with clients_lock:
        if publisher_username in subscriptions:
            # Message ordering is preserved per publisher via TCP 
            for sub_socket in list(subscriptions[publisher_username]):
                try:
                    sub_socket.sendall(encoded_msg)
                except:
                    remove_client(sub_socket)

def broadcast_to_room(message, room, sender_socket=None):
    """Broadcasts messages only within current room[cite: 79]."""
    logging.info(f"ROOM [{room}] {message}")
    encoded_msg = message.encode('utf-8')
    with clients_lock:
        for client_socket, client_room in client_rooms.items():
            if client_room == room and client_socket != sender_socket:
                try:
                    client_socket.sendall(encoded_msg)
                except:
                    remove_client(client_socket)

def remove_client(client_socket):
    """Handles client disconnects and cleans up subscriptions[cite: 63, 86]."""
    with clients_lock:
        user = clients.pop(client_socket, None)
        client_rooms.pop(client_socket, None)
        # Prune subscriber lists
        for target in subscriptions:
            subscriptions[target].discard(client_socket)
        try:
            client_socket.close()
        except:
            pass
        return user

def handle_commands(client_socket, username, msg):
    """Processes commands for rooms and subscriptions[cite: 79, 82]."""
    parts = msg.split()
    cmd = parts[0].lower()

    if cmd == "/rooms":
        with clients_lock:
            unique_rooms = set(client_rooms.values())
        client_socket.sendall(f"Available rooms: {', '.join(unique_rooms)}".encode())
        return True

    elif cmd == "/join" and len(parts) > 1:
        new_room = parts[1]
        old_room = client_rooms.get(client_socket, "lobby")
        broadcast_to_room(f"🔴 {username} left the room.", old_room, sender_socket=client_socket)
        with clients_lock:
            client_rooms[client_socket] = new_room
        client_socket.sendall(f"SUCCESS: Joined room {new_room}".encode())
        broadcast_to_room(f"🟢 {username} joined the room.", new_room, sender_socket=client_socket)
        return True

    elif cmd == "/subscribe" and len(parts) > 1:
        target_user = parts[1]
        with clients_lock:
            if target_user not in subscriptions:
                subscriptions[target_user] = set()
            subscriptions[target_user].add(client_socket) # Central enforcement 
        client_socket.sendall(f"SUCCESS: Subscribed to {target_user}\n".encode())
        return True

    elif cmd == "/unsubscribe" and len(parts) > 1:
        target_user = parts[1]
        with clients_lock:
            if target_user in subscriptions:
                subscriptions[target_user].discard(client_socket)
        client_socket.sendall(f"SUCCESS: Unsubscribed from {target_user}\n".encode())
        return True
        
    return False

def handle_authentication(client_socket, addr):
    """Secure LOGIN handler using bcrypt[cite: 66, 67]."""
    while True:
        try:
            client_socket.sendall("AUTH_REQUIRED: LOGIN <user> <pass>".encode())
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data: return None

            parts = data.split()
            if len(parts) == 3 and parts[0].upper() == "LOGIN":
                _, username, password = parts
                if username in user_db and bcrypt.checkpw(password.encode(), user_db[username]):
                    with clients_lock:
                        # Reject Duplicate Login Policy [cite: 71]
                        if username in clients.values():
                            client_socket.sendall("ERROR: User already logged in.\n".encode())
                            continue
                        clients[client_socket] = username
                        client_rooms[client_socket] = "lobby"
                    client_socket.sendall(f"SUCCESS: Welcome {username}\n".encode())
                    return username
            client_socket.sendall("ERROR: Invalid credentials.\n".encode())
        except:
            return None

def handle_client(client_socket, addr):
    """Main client loop managing rooms and pub-sub[cite: 62, 86]."""
    username = handle_authentication(client_socket, addr)
    if not username:
        remove_client(client_socket)
        return

    broadcast_to_room(f"🟢 {username} joined the lobby.", "lobby")

    try:
        while True:
            msg = client_socket.recv(1024).decode('utf-8')
            if not msg: break
            
            if msg.startswith("/"):
                if handle_commands(client_socket, username, msg):
                    continue
            
            # Publish to subscribers 
            multicast_to_subscribers(msg, username)
            # Also maintain room chat [cite: 79]
            current_room = client_rooms.get(client_socket, "lobby")
            broadcast_to_room(f"{username}: {msg}", current_room, sender_socket=client_socket)
    except:
        pass
    finally:
        user = remove_client(client_socket)
        if user:
            logging.info(f"User '{user}' session ended.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    logging.info(f"Pub-Sub Server listening on {PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()