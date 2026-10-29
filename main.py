"""SentinelOS - Mini Endpoint Detection & Response System.

Usage:
    python main.py          # open the dashboard (GUI)
    python main.py --cli    # console mode (no GUI)
"""
import sys
import time


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
    if "--cli" in sys.argv:
        run_cli()
    else:
        from sentinelos.dashboard import run
        run()
