"""Small helpers used when the server starts from the terminal."""
import socket
import getpass

from .auth import ROLES


def lan_ip():
    """This computer's address on the local network (no data is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ensure_admin(users):
    """On the very first run there are no accounts: create the admin now."""
    if users.users:
        return
    print("\nFirst run - create the ADMIN account for the dashboard.")
    while True:
        name = input("Admin username: ").strip() or "admin"
        pw = getpass.getpass("Admin password (min 6 chars, hidden while typing): ")
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match, try again.\n")
            continue
        try:
            users.add(name, pw, "admin")
            print(f"Admin '{name}' created. Add the teacher's account from the Users page.\n")
            return
        except ValueError as exc:
            print(f"Error: {exc}\n")


def add_user_cli(users):
    name = input("Username: ").strip()
    role = input(f"Role {ROLES}: ").strip() or "viewer"
    pw = getpass.getpass("Password: ")
    users.add(name, pw, role)
    print(f"User '{name}' saved as {role}.")
