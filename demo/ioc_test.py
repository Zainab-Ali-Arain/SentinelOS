"""SAFE TEST: connects to 127.0.0.66, an address listed in iocs.json as a demo IoC.
127.0.0.66 is part of the loopback range, so no traffic leaves this computer.
Expected result: ioc_match -> CRITICAL alert for this process."""
import os
import time
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.66", 8443))
server.listen(1)
client = socket.create_connection(("127.0.0.66", 8443))
conn, _ = server.accept()
print(f"IoC test running, PID {os.getpid()} (40 seconds)...")
time.sleep(40)
for s in (client, conn, server):
    s.close()
print("Done.")
