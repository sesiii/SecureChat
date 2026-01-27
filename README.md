# Problem 1: Thread-Based Chat Server

## Overview
[cite_start]This implementation replaces the `asyncio` (Event Loop) model with a **Thread-per-client** architecture using Python's `socket` and `threading` libraries[cite: 9, 10].

## Logic & Design Choices

### 1. Blocking I/O and Threads
In the original code, `asyncio` handled multiple connections on a single thread by "yielding" during I/O. In this version:
* [cite_start]The main thread runs a `while True` loop calling `server.accept()`, which **blocks** until a new client connects.
* [cite_start]Upon connection, a new `threading.Thread` is spawned to manage that specific client's lifecycle (`handle_client`)[cite: 11].
* Inside each thread, `socket.recv()` is a blocking call that waits for data from that specific client without stopping other clients' threads.

### 2. Shared State Management
[cite_start]Because multiple threads are accessing the `clients` dictionary simultaneously (to add, remove, or iterate for broadcasting), a **`threading.Lock()`** is used[cite: 9]. 
* **Why?** To prevent `RuntimeError: dictionary changed size during iteration` or race conditions where two threads try to modify the client list at the same time.

### 3. Graceful Disconnection
[cite_start]The server handles client exits in two ways[cite: 11]:
* **Clean Exit:** Detecting an empty string (`if not message:`) which signifies the client closed the socket.
* **Dirty Exit:** Catching `ConnectionResetError` if the client process is killed abruptly.
* In both cases, the `finally` block ensures the client is removed from the shared state and the socket is closed.

## Problem 4: Chat Rooms

### 1. Room Isolation
* [cite_start]**Logic:** Instead of a global broadcast, the server now maps every socket to a `room_name` in the `client_rooms` dictionary.
* [cite_start]**Default State:** New users are automatically placed in the `lobby` upon successful login.
* [cite_start]**Filtering:** The `broadcast_to_room` function iterates through connected clients and only sends the data if `client_room == target_room`.

### [cite_start]2. Supported Commands 
* `/join <room>`: Switches the user's current room state and notifies both the old and new rooms.
* `/leave`: Returns the user to the default `lobby`.
* `/rooms`: Lists all currently active rooms that have at least one occupant.

### 3. Thread Safety
* [cite_start]Updates to `client_rooms` are performed within the `clients_lock` to ensure that a broadcast doesn't occur while a user is mid-transition between rooms[cite: 17, 34].
## How to Run
1. **Start the Server:**
   ```bash
   python server.py