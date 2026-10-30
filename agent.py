"""SentinelOS Agent - install this on a group member's laptop.

It only MONITORS this laptop and SENDS the results to the dashboard laptop.
It has no dashboard and gives nobody access to this laptop.

    python agent.py                                  # asks for the server IP and a name
    python agent.py --server 192.168.1.5 --name Ali  # or pass them directly
"""
import os
import sys


def ask(flag, question, default=""):
    if flag in sys.argv and sys.argv.index(flag) + 1 < len(sys.argv):
        return sys.argv[sys.argv.index(flag) + 1]
    answer = input(f"{question}{f' [{default}]' if default else ''}: ").strip()
    return answer or default


if __name__ == "__main__":
    print("=" * 50)
    print("  SentinelOS Agent")
    print("  Monitors this laptop and reports to the dashboard.")
    print("=" * 50)
    server = ask("--server", "Dashboard laptop IP (e.g. 192.168.1.5)")
    if not server:
        sys.exit("The dashboard IP is required.")
    name = ask("--name", "Name for this laptop", os.environ.get("COMPUTERNAME", ""))
    if name:
        os.environ["SENTINEL_NAME"] = name  # must be set before sentinelos is imported

    from sentinelos.remote import run_agent
    try:
        run_agent(server)
    finally:
        if getattr(sys, "frozen", False):
            input("\nPress Enter to close...")  # keep the window open when double-clicked
