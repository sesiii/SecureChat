import socket
import threading
import sys
import ssl

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 1222

def receive_messages(secure_sock):
    while True:
        try:
            message = secure_sock.recv(4096).decode('utf-8')
            if not message:
                print("\n[System] Connection closed by server.")
                break
            print(f"\n{message}")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n[Error] Receiving message: {e}")
            break

def start_client(host, port):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    try:
        context.load_verify_locations('server.crt')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    except Exception as e:
        print(f"[Error] Failed to load server.crt: {e}")
        return

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        secure_client = context.wrap_socket(raw_sock, server_hostname=host)
        print(f"[System] Connecting to {host}:{port} via TLS...")
        secure_client.connect((host, port))
        print("[System] Secure connection established and verified.")
    except ssl.SSLCertVerificationError as e:
        print(f"[Security Error] Could not verify server identity: {e}")
        return
    except ConnectionRefusedError:
        print(f"[Error] Could not connect to server at {host}:{port}. Is it running?")
        return
    except Exception as e:
        print(f"[Error] TLS Handshake failed: {e}")
        return

    receiver_thread = threading.Thread(target=receive_messages, args=(secure_client,), daemon=True)
    receiver_thread.start()

    print("\n--- Command Guide ---")
    print("1. LOGIN <username> <password> ")
    print("2. /join <room_name> ")
    print("3. /rooms (List active rooms) ")
    print("4. /subscribe <username> ")
    print("5. /logout or /quit")
    print("----------------------\n")

    try:
        while True:
            msg = input("> ").strip()
            if not msg:
                continue
            if msg.lower() == '/quit':
                break
            secure_client.sendall(msg.encode('utf-8'))
            if msg.lower() == '/logout':
                print("[System] Logging out...")
                break
    except KeyboardInterrupt:
        print("\n[System] Interrupted by user.")
    finally:
        secure_client.close()
        print("[System] Client closed.")

if __name__ == "__main__":
    target_host = DEFAULT_HOST
    target_port = DEFAULT_PORT

    if len(sys.argv) > 1:
        try:
            target_port = int(sys.argv[1])
        except ValueError:
            print("[Usage] python3 client.py <port>")
            sys.exit(1)

    start_client(target_host, target_port)
