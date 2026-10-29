"""SentinelOS - Mini Endpoint Detection & Response System.

Usage:
    python main.py                                  # web dashboard on http://localhost:8000
    python main.py --agent SERVER_IP [--name NAME]  # monitor this laptop, report to the server
    python main.py --add-user                       # create a dashboard account
    python main.py --cli                            # console mode (no dashboard)
"""
import os
import sys
import time


def arg_value(flag):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        sys.exit(f"Missing value after {flag}")
    return None


def run_cli():
    from sentinelos.engine import SentinelEngine

    engine = SentinelEngine()
    engine.start()
    print("SentinelOS running in console mode. Press Ctrl+C to stop.\n")
    try:
        while True:
            state = engine.scan()
            s = state["system"]
            print("=" * 70)
            print(f"MINI EDR | Processes: {len(state['processes'])} | CPU: {s['cpu_percent']}%"
                  f" | RAM: {s['ram_used_percent']}% | Files: {state['monitored_files']}"
                  f" | Threat: {state['threat_level']}")
            print(f"{'PID':>7}  {'PROCESS':22} {'CPU%':>6} {'SCORE':>5}  {'RISK':8} REASONS")
            for p in state["processes"][:8]:
                print(f"{p['pid']:>7}  {p['name'][:22]:22} {p['cpu_percent']:>6} "
                      f"{p['score']:>5}  {p['level']:8} {', '.join(p['reasons'])}")
            for a in state["new_alerts"]:
                print(f"\n*** {a['level']} ALERT: {a['type']} | {a['process']} | PID={a['pid']}"
                      f" | score={a['score']} | {', '.join(a['reasons'])}")
            time.sleep(2)
    except KeyboardInterrupt:
        engine.stop()
        print("\nStopped.")


if __name__ == "__main__":
    name = arg_value("--name")
    if name:
        os.environ["SENTINEL_NAME"] = name  # must be set before sentinelos is imported
    if "--cli" in sys.argv:
        run_cli()
    elif "--agent" in sys.argv:
        from sentinelos.remote import run_agent
        run_agent(arg_value("--agent"))
    elif "--add-user" in sys.argv:
        from sentinelos.auth import UserStore
        from sentinelos.setup import add_user_cli
        add_user_cli(UserStore())
    else:
        from sentinelos.webapp import run_server
        run_server()
