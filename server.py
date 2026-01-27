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
clients = {}    # {socket: username}
client_rooms = {} # {socket: room_name} 
user_db = {
    "alice": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("letmein".encode(), bcrypt.gensalt()),
    "charlie": bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt()),
    "dave": bcrypt.hashpw("123456".encode(), bcrypt.gensalt())
}
clients_lock = threading.Lock()

def broadcast_to_room(message, room, sender_socket=None):
    """Broadcasts messages only to members of a specific room."""
    logging.info(f"[{room}] {message}")
    encoded_msg = message.encode('utf-8')
    
    with clients_lock:
        for client_socket, client_room in client_rooms.items():
            if client_room == room and client_socket != sender_socket:
                try:
                    client_socket.sendall(encoded_msg)
                except:
                    remove_client(client_socket)

def remove_client(client_socket):
    """Handles client cleanup and room exit[cite: 11, 27]."""
    with clients_lock:
        user = clients.pop(client_socket, None)
        room = client_rooms.pop(client_socket, None)
        try:
            client_socket.close()
        except:
            pass
        return user, room

def handle_commands(client_socket, username, msg):
    """Processes room-related commands."""
    parts = msg.split()
    cmd = parts[0].lower()

    if cmd == "/rooms":
        with clients_lock:
            unique_rooms = set(client_rooms.values())
        client_socket.sendall(f"Available rooms: {', '.join(unique_rooms)}".encode())
        return True

    elif cmd == "/join" and len(parts) > 1:
        new_room = parts[1]
        old_room = client_rooms[client_socket]
        
        broadcast_to_room(f"🔴 {username} left the room.", old_room, sender_socket=client_socket)
        
        with clients_lock:
            client_rooms[client_socket] = new_room
            
        client_socket.sendall(f"SUCCESS: Joined room {new_room}".encode())
        broadcast_to_room(f"🟢 {username} joined the room.", new_room, sender_socket=client_socket)
        return True

    elif cmd == "/leave":
        old_room = client_rooms[client_socket]
        broadcast_to_room(f"🔴 {username} left the room.", old_room, sender_socket=client_socket)
        
        with clients_lock:
            client_rooms[client_socket] = "lobby"
            
        client_socket.sendall("Returned to lobby.".encode())
        broadcast_to_room(f"🟢 {username} joined the room.", "lobby", sender_socket=client_socket)
        return True
        
    return False

def handle_authentication(client_socket, addr):
    """Standard authentication with default lobby assignment[cite: 14, 27]."""
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
                        if username in clients.values():
                            client_socket.sendall("ERROR: Already logged in.\n".encode())
                            continue
                        clients[client_socket] = username
                        client_rooms[client_socket] = "lobby" # Default lobby 
                    
                    client_socket.sendall(f"SUCCESS: Welcome {username} to lobby\n".encode())
                    return username
            client_socket.sendall("ERROR: Invalid credentials.\n".encode())
        except:
            return None

def handle_client(client_socket, addr):
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
            
            # Send to specific room members only 
            current_room = client_rooms[client_socket]
            broadcast_to_room(f"[{current_room}] {username}: {msg}", current_room, sender_socket=client_socket)
    except:
        pass
    finally:
        user, room = remove_client(client_socket)
        if user:
            broadcast_to_room(f"🔴 {user} left the chat.", room)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    logging.info(f"Room-based server listening on {PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()