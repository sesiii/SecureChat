import socket
import threading
import sys

HOST = '127.0.0.1'
PORT = 60008

def receive_messages(sock):
    """Thread function to constantly listen for messages from the server."""
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if not message:
                print("\nDisconnected from server.")
                break
            print(f"\n{message}")
            print("> ", end="", flush=True)
        except Exception:
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Could not connect to server.")
        return

    # Start a thread to receive messages so input doesn't block them
    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    try:
        while True:
            msg = input("> ")
            if msg.lower() == '/quit':
                break
            client.sendall(msg.encode('utf-8'))
    except KeyboardInterrupt:
        pass
    finally:
        client.close()

if __name__ == "__main__":
    start_client()