import socket
import threading
import bcrypt
import logging
import sys
import redis
import json
import signal
import ssl
import os

# --- Configuration ---
# Use 0.0.0.0 for Docker compatibility; otherwise 127.0.0.1 for local testing
HOST = '0.0.0.0' 
DEFAULT_PORT = 1222
# REDIS_HOST is pulled from environment for Docker [cite: 38, 46]
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = 6379

# Initialize Redis with decode_responses=True for easier string handling [cite: 37]
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# Logging setup to track server events [cite: 11]
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("chat_server.log"), logging.StreamHandler(sys.stdout)]
)

local_clients = {} # Local tracking of sockets for this instance [cite: 10]

# Hardcoded user database for testing Problem 2 [cite: 14]
user_db = {
    "alice": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("letmein".encode(), bcrypt.gensalt()),
    "dave": bcrypt.hashpw("123456".encode(), bcrypt.gensalt()),
    "eve": bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt())
}

# --- Redis Pub/Sub Logic (Problem 6) ---

def redis_listener():
    """Listens to Redis for messages published by ANY server instance[cite: 38, 39]."""
    pubsub = r.pubsub()
    pubsub.subscribe("global_chat")
    logging.info("Redis Pub/Sub listener started.")
    
    for message in pubsub.listen():
        if message['type'] == 'message':
            data = json.loads(message['data'])
            target_room = data['room']
            msg_text = data['message']
            sender = data['sender']
            
            # Check local clients to see who should receive this message
            for uname, sock in local_clients.items():
                is_in_room = r.sismember(f"room:{target_room}", uname)
                is_subscriber = r.sismember(f"subscribers:{sender}", uname)
                
                # Deliver if in the same room (Prob 4) or subscribed (Prob 5) [cite: 27, 32]
                if (is_in_room or is_subscriber) and uname != sender:
                    try:
                        prefix = f"[{target_room}]" if is_in_room else "[Subbed]"
                        sock.sendall(f"{prefix} {sender}: {msg_text}".encode())
                    except:
                        pass

def publish_message(sender, room, message):
    """Broadcasting utility that pushes messages to Redis."""
    payload = json.dumps({"sender": sender, "room": room, "message": message})
    r.publish("global_chat", payload)

# --- Command Handler (Problem 4 & 5) ---

def handle_commands(client_socket, username, msg):
    parts = msg.split()
    cmd = parts[0].lower()

    if cmd == "/logout":
        return "LOGOUT"
    
    if cmd == "/rooms":
        room_keys = r.keys("room:*")
        room_names = [key.split(":")[1] for key in room_keys]
        response = f"Rooms: {', '.join(room_names)}" if room_names else "No active rooms."
        client_socket.sendall(response.encode())
        return True

    if cmd == "/join" and len(parts) > 1: # [cite: 27]
        new_room = parts[1]
        old_room = r.hget(f"session:{username}", "room")
        if old_room:
            r.srem(f"room:{old_room}", username)
        r.sadd(f"room:{new_room}", username)
        r.hset(f"session:{username}", "room", new_room)
        client_socket.sendall(f"SUCCESS: Joined {new_room}".encode())
        publish_message("Server", new_room, f"{username} joined.")
        return True

    if cmd == "/subscribe" and len(parts) > 1: # [cite: 30]
        target = parts[1]
        r.sadd(f"subscribers:{target}", username)
        client_socket.sendall(f"SUCCESS: Subscribed to {target}".encode())
        return True

    if cmd == "/unsubscribe" and len(parts) > 1: # [cite: 30]
        target = parts[1]
        r.srem(f"subscribers:{target}", username)
        client_socket.sendall(f"SUCCESS: Unsubscribed from {target}".encode())
        return True
    
    return False

# --- Authentication (Problem 2 & 3) ---

def handle_authentication(client_socket, addr):
    while True:
        try:
            client_socket.sendall("AUTH_REQUIRED: LOGIN <user> <pass>".encode())
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data: return None
            
            parts = data.split()
            if len(parts) == 3 and parts[0].upper() == "LOGIN":
                _, username, password = parts
                # Secure password check using bcrypt [cite: 14]
                if username in user_db and bcrypt.checkpw(password.encode(), user_db[username]):
                    # Problem 3: Reject Duplicate Login 
                    if r.hexists(f"session:{username}", "status"):
                        client_socket.sendall("ERROR: User already logged in elsewhere.\n".encode())
                        continue
                    
                    # Store session in Redis Hash [cite: 37]
                    r.hset(f"session:{username}", mapping={"status": "online", "room": "lobby"})
                    r.sadd("room:lobby", username)
                    local_clients[username] = client_socket
                    
                    logging.info(f"User '{username}' authenticated.")
                    client_socket.sendall(f"SUCCESS: Welcome {username}. You are in lobby.\n".encode())
                    return username
            client_socket.sendall("ERROR: Invalid credentials.\n".encode())
        except:
            return None

def handle_client(client_socket, addr):
    """Problem 1: Handles the client lifecycle in a dedicated thread[cite: 10, 11]."""
    username = handle_authentication(client_socket, addr)
    if not username: return

    try:
        while True:
            msg = client_socket.recv(1024).decode('utf-8')
            if not msg: break
            if msg.startswith("/"):
                res = handle_commands(client_socket, username, msg)
                if res == "LOGOUT": break
                if res: continue
            
            # Default room is lobby [cite: 27]
            curr_room = r.hget(f"session:{username}", "room") or "lobby"
            publish_message(username, curr_room, msg)
    finally:
        # Cleanup [cite: 11]
        curr_room = r.hget(f"session:{username}", "room")
        if curr_room: r.srem(f"room:{curr_room}", username)
        r.delete(f"session:{username}")
        local_clients.pop(username, None)
        client_socket.close()

# --- Lifecycle & TLS (Problem 7 & 8) ---

def cleanup_handler(sig, frame):
    logging.info("Shutting down... Cleaning Redis.")
    r.flushdb() # Optional: Clear all if this is the only server
    sys.exit(0)

def start_server(port):
    signal.signal(signal.SIGINT, cleanup_handler)
    threading.Thread(target=redis_listener, daemon=True).start()
    
    # Problem 7: TLS Secure Transport 
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    raw_socket.bind((HOST, port))   
    # raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # raw_socket.bind((HOST, port))
    raw_socket.listen()
    
    # Wrap with TLS [cite: 42, 43]
    secure_server = context.wrap_socket(raw_socket, server_side=True)
    
    logging.info(f"SECURE SERVER on Port {port}")
    while True:
        try:
            conn, addr = secure_server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except OSError:
            break

if __name__ == "__main__":
    port_to_use = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    start_server(port_to_use)