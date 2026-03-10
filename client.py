import socket
import threading
import sys
import ssl

# Default configurations
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 1222

def receive_messages(secure_sock):
    """
    Thread function to constantly listen for messages from the server.
    Handles incoming chat messages and system notifications.
    """
    while True:
        try:
            # Receive data from the encrypted TLS tunnel
            message = secure_sock.recv(4096).decode('utf-8')
            if not message:
                print("\n[System] Connection closed by server.")
                break
            
            # Print the received message and restore the input prompt
            print(f"\n{message}")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n[Error] Receiving message: {e}")
            break

def start_client(host, port):
    """
    Initializes a secure TCP connection to the chat server using TLS.
    """
    # PROBLEM 7: Create a TLS context
    # We use Purpose.SERVER_AUTH because the client is verifying the server [cite: 43]
    context = ssl.create_default_context()
    
    # For testing with self-signed certificates:
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE 

    # Create a standard TCP socket
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # PROBLEM 7: Wrap the raw socket with TLS before connecting [cite: 42, 43]
        secure_client = context.wrap_socket(raw_sock, server_hostname=host)
        
        print(f"[System] Connecting to {host}:{port} via TLS...")
        secure_client.connect((host, port))
        print("[System] Secure connection established.")
        
    except ConnectionRefusedError:
        print(f"[Error] Could not connect to server at {host}:{port}. Is the server running?")
        return
    except Exception as e:
        print(f"[Error] TLS Handshake failed: {e}")
        return

    # PROBLEM 1: One thread for receiving to avoid blocking the user input 
    receiver_thread = threading.Thread(target=receive_messages, args=(secure_client,), daemon=True)
    receiver_thread.start()

    print("\n--- Command Guide ---")
    print("1. LOGIN <username> <password>")
    print("2. /join <room_name>")
    print("3. /rooms (List active rooms)")
    print("4. /subscribe <username>")
    print("5. /logout or /quit")
    print("----------------------\n")

    try:
        while True:
            # Main thread handles user input
            msg = input("> ").strip()
            
            if not msg:
                continue
                
            if msg.lower() == '/quit':
                break
            
            # Send the message/command through the secure tunnel
            secure_client.sendall(msg.encode('utf-8'))
            
            # If the user sends /logout, the server loop usually breaks; 
            # we can exit the client loop here as well.
            if msg.lower() == '/logout':
                print("[System] Logging out...")
                break

    except KeyboardInterrupt:
        print("\n[System] Interrupted by user.")
    finally:
        secure_client.close()
        print("[System] Client closed.")

if __name__ == "__main__":
    # Allows running as: python3 client.py 1222 OR python3 client.py 1223
    # This supports testing the multi-server Problem 6 requirement 
    target_host = DEFAULT_HOST
    target_port = DEFAULT_PORT

    if len(sys.argv) > 1:
        try:
            target_port = int(sys.argv[1])
        except ValueError:
            print("[Usage] python3 client.py <port>")
            sys.exit(1)

    start_client(target_host, target_port)