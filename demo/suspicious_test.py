"""SAFE END-TO-END DEMO (project section 18).

This harmless program behaves *suspiciously* so the EDR has something to
detect. It does NOT steal, encrypt, hide, persist or contact the internet:
  1. copies itself to the TEMP folder and runs from there   -> unusual_path
  2. burns CPU                                                -> high_cpu
  3. rapidly edits text files inside test_zone only          -> file_burst + integrity
  4. opens a LOCAL connection (127.0.0.1) on port 4444        -> suspicious_network
It stops by itself after 90 seconds, or terminate it from the dashboard.
"""
import os
import sys
import time
import shutil
import socket
import tempfile
import threading
import subprocess

DURATION = 90


def launcher():
    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    copy = os.path.join(tempfile.gettempdir(), "sentinel_demo_payload.py")
    shutil.copy(os.path.abspath(__file__), copy)
    child = subprocess.Popen([sys.executable, copy, "--payload", project])
    print(f"Demo started from {copy}")
    print(f"Watch the dashboard for PID {child.pid}. Waiting...")
    child.wait()
    print("Demo finished.")


def payload(project):
    stop = time.time() + DURATION

    def cpu():
        while time.time() < stop:
            pass

    def network():
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", 4444))
        except OSError:
            print("Port 4444 is busy (is another demo still running?) - skipping network part")
            return
        server.listen(1)
        client = socket.create_connection(("127.0.0.1", 4444))
        conn, _ = server.accept()
        while time.time() < stop:
            time.sleep(1)
        for s in (client, conn, server):
            s.close()

    def files():
        burst = os.path.join(project, "test_zone", "burst")
        protected = os.path.join(project, "test_zone", "protected")
        os.makedirs(burst, exist_ok=True)
        i = 0
        while time.time() < stop:
            with open(os.path.join(burst, f"demo_{i % 100}.txt"), "w") as f:
                f.write(f"harmless demo write {i}\n")
            if i % 50 == 0 and os.path.isdir(protected):
                for name in os.listdir(protected):  # simulate unauthorized edit
                    with open(os.path.join(protected, name), "a") as f:
                        f.write("changed by demo\n")
            i += 1
            time.sleep(0.02)

    threads = [threading.Thread(target=t, daemon=True) for t in (cpu, network, files)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    if "--payload" in sys.argv:
        payload(sys.argv[sys.argv.index("--payload") + 1])
    else:
        launcher()
