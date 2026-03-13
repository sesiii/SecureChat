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

HOST = '0.0.0.0'
DEFAULT_PORT = 1222
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("chat_server.log"), logging.StreamHandler(sys.stdout)]
)

local_clients = {}

user_db = {
    "alice": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("letmein".encode(), bcrypt.gensalt()),
    "dave": bcrypt.hashpw("123456".encode(), bcrypt.gensalt()),
    "eve": bcrypt.hashpw("qwerty".encode(), bcrypt.gensalt())
}

def redis_listener():
    pubsub = r.pubsub()
    pubsub.subscribe("global_chat")
    logging.info("Redis Pub/Sub listener started.")
    for message in pubsub.listen():
        if message['type'] == 'message':
            data = json.loads(message['data'])
            target_room = data['room']
            msg_text = data['message']
            sender = data['sender']
            for uname, sock in local_clients.items():
                is_in_room = r.sismember(f"room:{target_room}", uname)
                is_subscriber = r.sismember(f"subscribers:{sender}", uname)
                if (is_in_room or is_subscriber) and uname != sender:
                    try:
                        prefix = f"[{target_room}]" if is_in_room else "[Subbed]"
                        sock.sendall(f"{prefix} {sender}: {msg_text}".encode())
                    except:
                        pass

def publish_message(sender, room, message):
    payload = json.dumps({"sender": sender, "room": room, "message": message})
    r.publish("global_chat", payload)

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
    if cmd == "/join" and len(parts) > 1:
        new_room = parts[1]
        old_room = r.hget(f"session:{username}", "room")
        if old_room:
            r.srem(f"room:{old_room}", username)
        r.sadd(f"room:{new_room}", username)
        r.hset(f"session:{username}", "room", new_room)
        client_socket.sendall(f"SUCCESS: Joined {new_room}".encode())
        publish_message("Server", new_room, f"{username} joined.")
        return True
    if cmd == "/subscribe" and len(parts) > 1:
        target = parts[1]
        r.sadd(f"subscribers:{target}", username)
        client_socket.sendall(f"SUCCESS: Subscribed to {target}".encode())
        return True
    if cmd == "/unsubscribe" and len(parts) > 1:
        target = parts[1]
        r.srem(f"subscribers:{target}", username)
        client_socket.sendall(f"SUCCESS: Unsubscribed from {target}".encode())
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
                    logging.info(f"User '{username}' authenticated.")
                    client_socket.sendall(f"SUCCESS: Welcome {username}. You are in lobby.\n".encode())
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

def cleanup_handler(sig, frame):
    logging.info("Shutting down... Cleaning Redis.")
    r.flushdb()
    sys.exit(0)

def start_server(port):
    signal.signal(signal.SIGINT, cleanup_handler)
    threading.Thread(target=redis_listener, daemon=True).start()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_socket.bind((HOST, port))
    raw_socket.listen()
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
