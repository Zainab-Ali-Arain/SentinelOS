"""SAFE TEST: opens a connection on Tor port 9150 over loopback (127.0.0.1).

9150 is the port the Tor Browser listens on, so SentinelOS treats a connection
to it as dark-web / Tor use. Because it is loopback, no traffic leaves this
computer and no real Tor network is touched.

Expected result: a DARK_WEB alert (HIGH) for this process, mapped to
MITRE T1090.003 (Multi-hop Proxy: Tor).
"""
import os
import time
import socket

TOR_PORT = 9150

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", TOR_PORT))
server.listen(1)
client = socket.create_connection(("127.0.0.1", TOR_PORT))
conn, _ = server.accept()
print(f"Dark-web (Tor) test running, PID {os.getpid()} (40 seconds)...")
print("Open the dashboard - a DARK_WEB alert should appear within a few seconds.")
time.sleep(40)
for s in (client, conn, server):
    s.close()
print("Done.")
