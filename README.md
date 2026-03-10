
# SecureChat: Distributed & Encrypted Chat System

SecureChat is a high-performance, multi-server chat application built with **Python**, **Redis**, and **Docker**. It features end-to-end **TLS encryption**, secure **bcrypt** password hashing, and a stateless architecture designed for horizontal scalability.

## 🏗 System Architecture

The application follows a distributed, stateless server model. Instead of storing user sessions in local memory, all state is delegated to a central Redis broker. This allows multiple server instances to operate as a single unified chat system.

### Core Components:
* **Chat Servers (Python):** Independent instances (Server 1 on port 1222, Server 2 on port 1223) that handle client socket connections and command parsing.
* **Redis Broker:** The "Source of Truth" for session management, room memberships, and cross-server message relay (Pub/Sub).
* **Secure Clients:** Python-based CLI tools that wrap standard TCP sockets in a **TLS 1.3** layer using the `ssl` module.

---

## 🛡 Features & Implementation Details

| Feature | Implementation Detail |
| :--- | :--- |
| **TLS Encryption** | All transport is wrapped in `ssl.SSLContext`. Plaintext connections are strictly rejected. |
| **Bcrypt Hashing** | Passwords verified using salted hashes; no plaintext storage in `user_db`. |
| **Stateless Servers** | Servers fetch session data from Redis, allowing horizontal scaling. |
| **Duplicate Login** | Enforces "Reject Duplicate Login" policy via Redis `hexists` checks. |
| **Pub/Sub Model** | Users can `/subscribe` to others to receive messages across different rooms. |
| **Dockerized** | Entire stack (Servers + Redis) deployable via `docker compose`. |

---

## 🛠 Redis Schema (Data Design)

To ensure consistency across multiple containers, the following Redis structures are utilized:

* **User Sessions (Hash):** `session:<username>` stores fields like `status` (online) and `room` (current location).
* **Room Membership (Set):** `room:<room_name>` contains a set of active usernames. Sets ensure O(1) complexity for joins/leaves.
* **Subscriptions (Set):** `subscribers:<username>` contains usernames of followers.
* **Global Relay (Pub/Sub):** The `global_chat` channel broadcasts messages to every server instance, which then delivers them to locally connected users.

---

## 🚀 Deployment Guide

### 1. Prerequisites
* Docker and Docker Compose V2 installed on WSL/Ubuntu.
* Python 3.9+ installed for the client-side.

### 2. Generate TLS Certificates

Run:
```bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

### 3. Launch with Docker Compose

Bring up the Redis broker and two separate server instances:
```bash
sudo docker compose up --build
```

**Note:** If port 6379 is busy, stop your local Redis service first: `sudo service redis-server stop`.

---

## 🧪 Demonstration Workflow

### Step 1: Connect Multiple Clients

Open two terminals on your host machine:
* Terminal 1: `python3 client.py 1222`
* Terminal 2: `python3 client.py 1223`

### Step 2: Authentication & Duplicate Check

* Terminal 1: `LOGIN alice password123`
* Terminal 2: Try `LOGIN alice password123`. The server will reject the duplicate session.
* Terminal 2: `LOGIN bob letmein`

### Step 3: Distributed Rooms 

* Alice (Port 1222): `/join IITKGP`
* Bob (Port 1223): `/join IITKGP`
* Alice: Sends "Hello from Server 1!"
* Bob: Receives the message on Server 2 via Redis Pub/Sub relay.

### Step 4: Subscriptions 

* Alice: `/join Lobby`
* Bob: `/join Research` (Users are now in different rooms).
* Bob: `/subscribe alice`
* Alice: Sends "Public Update."
* Bob: Receives message with [Subbed] prefix, proving cross-room delivery.

---

## 📜 Available Commands

* `LOGIN <user> <pass>`: Authenticate (Alice:password123, Bob:letmein, Dave:123456).
* `/join <room>`: Enter a chat room.
* `/rooms`: List all active chat rooms.
* `/subscribe <user>`: Follow a specific user.
* `/logout`: Exit securely and clear Redis session.

