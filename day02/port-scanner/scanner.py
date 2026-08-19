import socket
import time
from threading import Thread


print()
print("SIMPLE PORT SCANNER")
print()


target = input("Enter target IP or hostname: ")

target_ip = socket.gethostbyname(target)
print(f"\nScanning {target} ({target_ip})...")

start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))

common_services = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

start_time = time.time()

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target_ip, port))
    if result == 0:
        service = common_services.get(port, "Unknown")
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode().strip()
        except:
            banner = ""
        if banner:
            print(f"Port {port} is OPEN  [{service}]  Banner: {banner[:50]}")
        else:
            print(f"Port {port} is OPEN  [{service}]")
    s.close()


threads = []
for port in range(start_port , end_port+1):
    t = Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()


for t in threads:
    t.join()




end_time = time.time()
print(f"\nScan completed in {end_time - start_time:.2f} seconds")
