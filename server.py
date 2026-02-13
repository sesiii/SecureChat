import socket
import threading
import bcrypt
import logging
import sys
import redis
import json
import signal

# --- Configuration ---
HOST = '127.0.0.1'
# Default port if none provided via command line
DEFAULT_PORT = 60005
REDIS_HOST = 'localhost'
REDIS_PORT = 6379

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# Update local_clients to be unique to this specific server process
local_clients = {} 

user_db = {
    "alice": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("letmein".encode(), bcrypt.gensalt()),
    "dave": bcrypt.hashpw("123456".encode(), bcrypt.gensalt()),
    "eve": bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt())
}


def redis_listener():
    """Background thread running on ALL servers."""
    pubsub = r.pubsub()
    pubsub.subscribe("global_chat")
    
    for message in pubsub.listen():
        if message['type'] == 'message':
            data = json.loads(message['data'])
            target_room = data['room']
            msg_text = data['message']
            sender = data['sender']
            
            # This instance only looks at clients physically connected to IT
            for uname, sock in local_clients.items():
                # Check global Redis state for room membership
                is_in_room = r.sismember(f"room:{target_room}", uname)
                is_subscriber = r.sismember(f"subscribers:{sender}", uname)
                
                if (is_in_room or is_subscriber) and uname != sender:
                    try:
                        # Deliver the message across the distributed network
                        prefix = f"[{target_room}]" if is_in_room else "[Subbed]"
                        sock.sendall(f"{prefix} {sender}: {msg_text}".encode())
                    except Exception:
                        pass

def publish_message(sender, room, message):
    """Publishes message to Redis so ALL server instances can hear it."""
    payload = json.dumps({"sender": sender, "room": room, "message": message})
    r.publish("global_chat", payload)

# --- Command & Auth Logic ---

def handle_commands(client_socket, username, msg):
    parts = msg.split()
    cmd = parts[0].lower()

    if cmd == "/logout":
        client_socket.sendall("SUCCESS: You have been logged out.".encode())
        return "LOGOUT"
    
    if cmd == "/rooms":
        room_keys = r.keys("room:*")
        room_names = [key.split(":")[1] for key in room_keys]
        response = f"Available Rooms: {', '.join(room_names)}" if room_names else "No active rooms."
        client_socket.sendall(response.encode())
        return True

    if cmd == "/join" and len(parts) > 1:
        new_room = parts[1]
        old_room = r.hget(f"session:{username}", "room")
        if old_room:
            r.srem(f"room:{old_room}", username)
        r.sadd(f"room:{new_room}", username)
        r.hset(f"session:{username}", "room", new_room)
        client_socket.sendall(f"SUCCESS: Joined room {new_room}".encode())
        publish_message("Server", new_room, f"{username} joined.")
        return True

    if cmd == "/subscribe" and len(parts) > 1:
        target_user = parts[1]
        r.sadd(f"subscribers:{target_user}", username)
        client_socket.sendall(f"SUCCESS: Subscribed to {target_user}".encode())
        return True

    if cmd == "/unsubscribe" and len(parts) > 1:
        target_user = parts[1]
        r.srem(f"subscribers:{target_user}", username)
        client_socket.sendall(f"SUCCESS: Unsubscribed from {target_user}".encode())
        return True
    
    return False

def handle_authentication(client_socket, addr):
    while True:
        try:
            client_socket.sendall("AUTH_REQUIRED: LOGIN <user> <pass>".encode())
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data: return None
            parts = data.split()
            if len(parts) == 3 and parts[0].upper() == "LOGIN":
                _, username, password = parts
                if username in user_db and bcrypt.checkpw(password.encode(), user_db[username]):
                    if r.hexists(f"session:{username}", "status"):
                        client_socket.sendall("ERROR: User already logged in elsewhere.\n".encode())
                        continue
                    
                    r.hset(f"session:{username}", mapping={"status": "online", "room": "lobby"})
                    r.sadd("room:lobby", username)
                    local_clients[username] = client_socket
                    
                    logging.info(f"User '{username}' logged into this instance.")
                    client_socket.sendall(f"SUCCESS: Welcome {username}.\n".encode())
                    return username
            client_socket.sendall("ERROR: Invalid credentials.\n".encode())
        except:
            return None

def handle_client(client_socket, addr):
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
            
            curr_room = r.hget(f"session:{username}", "room") or "lobby"
            publish_message(username, curr_room, msg)
    finally:
        curr_room = r.hget(f"session:{username}", "room")
        if curr_room: r.srem(f"room:{curr_room}", username)
        r.delete(f"session:{username}")
        local_clients.pop(username, None)
        client_socket.close()
        logging.info(f"User '{username}' session cleared.")

# --- Server Lifecycle ---

def cleanup_handler(sig, frame):
    logging.info("Server shutting down. Cleaning up Redis...")
    # Optional: Use r.flushdb() ONLY if you want to kick EVERYONE off all instances.
    # Otherwise, just let individual threads clean up their own sessions.
    sys.exit(0)

def start_server(port):
    signal.signal(signal.SIGINT, cleanup_handler)
    
    # Start the global Redis listener
    threading.Thread(target=redis_listener, daemon=True).start()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen()
    
    logging.info(f"SERVER STARTED on Port {port}. Waiting for connections...")
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except OSError:
            break

if __name__ == "__main__":
    # Get port from command line: python3 server.py 60006
    port_to_use = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    
    # Configure logging to include the port so you can tell which server is which
    logging.basicConfig(
        level=logging.INFO,
        format=f'%(asctime)s [PORT {port_to_use}] %(message)s',
        handlers=[logging.FileHandler("chat_server.log"), logging.StreamHandler(sys.stdout)]
    )
    
    start_server(port_to_use)