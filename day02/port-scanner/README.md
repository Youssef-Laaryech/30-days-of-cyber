# Day 02 — Simple Port Scanner

## What I Built

A multithreaded TCP port scanner that scans a target for open ports, identifies running services, and grabs banners — all built from scratch using Python's `socket` and `threading` modules.

---

## How It Works

```
python scanner.py
```

Enter a target (IP or hostname), a port range, and the scanner checks each port for open connections, reports what service is running, and attempts to read the service's banner.

Example output:
```
Scanning scanme.nmap.org (45.33.32.156)...
Port 22 is OPEN  [SSH]  Banner: SSH-2.0-OpenSSH_7.4
Port 25 is OPEN  [SMTP]  Banner: 220 ack.nmap.org ESMTP Postfix
Port 80 is OPEN  [HTTP]  Banner: HTTP/1.1 403 Forbidden

Scan completed in 1.09 seconds
```

---

## Features & Why I Added Them

### 1. TCP Socket Connection
**What:** Uses `socket.connect_ex()` to attempt a TCP 3-way handshake on each port.  
**Why:** The handshake is definitive — if it completes, something is listening. This is how all TCP port scanners work fundamentally.

### 2. Timeout (`settimeout(1)`)
**What:** Limits how long we wait for a response to 1 second.  
**Why:** Without a timeout, if a port is filtered (firewall silently drops packets), the program would hang forever waiting for a response that will never come. The timeout lets us give up and move on.

### 3. Hostname Resolution (`gethostbyname`)
**What:** Converts a hostname like `scanme.nmap.org` into its IP address.  
**Why:** Two reasons — it shows the user what IP they're actually hitting, and it avoids resolving the hostname repeatedly on every port (resolve once, use the IP for all connections).

### 4. Service Identification
**What:** A dictionary mapping common port numbers to service names.  
**Why:** Knowing port 22 is open is useful. Knowing it's SSH is actionable. In real pentesting, identifying services is the first step before looking for vulnerabilities.

### 5. Banner Grabbing (`sendall` + `recv`)
**What:** After connecting to an open port, sends a basic request and reads whatever the service sends back.  
**Why:** Banners reveal exact software versions (like `SSH-2.0-OpenSSH_7.4`). An attacker uses this to search for known vulnerabilities in that specific version. A defender uses this to identify outdated software that needs patching.

### 6. Timing (`time.time()`)
**What:** Records how long the scan took.  
**Why:** Performance awareness. When scanning large ranges, you need to know if your scanner is practical. Also lets you compare before/after adding threading.

### 7. Multithreading
**What:** Instead of scanning ports one-by-one (sequential), scans many ports simultaneously using threads.  
**Why:** Without threading, 500 ports with a 1-second timeout = up to 500 seconds worst case. With threading, all 500 ports are checked in parallel = ~1 second. This is the difference between a toy and a usable tool.

---

## Concepts I Learned

- **TCP vs UDP** — TCP uses a 3-way handshake (SYN → SYN-ACK → ACK), making it reliable and scannable. UDP is fire-and-forget with no clear "I'm open" signal.
- **Sockets** — The programming interface for network connections. `AF_INET` = IPv4, `SOCK_STREAM` = TCP.
- **`connect_ex()` vs `connect()`** — Both try to connect, but `connect_ex` returns an error code (0 = success) instead of crashing on failure.
- **Banner grabbing** — Reading what a service announces about itself after a connection is made.
- **Threading** — Running multiple operations concurrently so I/O-bound tasks (like waiting for network responses) don't block each other.

---

## Project Structure

```
port-scanner/
├── scanner.py    # The scanner (socket + threading + banner grab)
└── README.md     # This file
```

---

**#30DaysOfCyber**
