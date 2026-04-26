#!/usr/bin/env python3
"""
Bare-metal (no Mininet) test harness for PQC TLS DDoS experiments.

Orchestrates a 3-phase experiment against a REMOTE server:
  1. Pre-attack baseline:  Client connects alone
  2. Attack phase:         Bots launched locally, client continues during DDoS
  3. Post-attack recovery: Bots killed, client continues

The server must already be running on the target machine.

Usage:
    python3 attack.py --server-ip 192.168.1.100 --bots 5 --threads 10 --duration 60
    python3 attack.py --server-ip 10.0.0.1 --bots 3 --threads 20 --duration 45 --client-interval 1000
"""

import argparse
import os
import signal
import subprocess
import sys
import time


def run_experiment(args):
    project_dir = os.path.dirname(os.path.abspath(__file__))
    bot_bin = os.path.join(project_dir, "bot")
    client_bin = os.path.join(project_dir, "pqc_client")

    # Validate binaries exist
    for path, name in [(bot_bin, "bot"), (client_bin, "pqc_client")]:
        if not os.path.isfile(path):
            print(f"[!] Binary '{name}' not found at {path}")
            print(f"    Run 'make pqc-all' first.")
            sys.exit(1)

    server_ip = args.server_ip

    # Phase durations
    phase_duration = args.duration // 3
    baseline_dur = phase_duration
    attack_dur = phase_duration
    recovery_dur = args.duration - 2 * phase_duration  # absorb remainder

    print("=" * 50)
    print("  PQC TLS DDoS Experiment (3-Phase, Bare-Metal)")
    print("=" * 50)
    print(f"  Server IP      : {server_ip}")
    print(f"  Bots           : {args.bots}")
    print(f"  Threads/bot    : {args.threads}")
    print(f"  Attack mode    : {args.mode}")
    print(f"  Total duration : {args.duration}s")
    print(f"    Phase 1 (baseline)  : {baseline_dur}s")
    print(f"    Phase 2 (attack)    : {attack_dur}s")
    print(f"    Phase 3 (recovery)  : {recovery_dur}s")
    print(f"  Client interval: {args.client_interval}ms")
    print("=" * 50)

    # Remove stale metrics files
    for f in ["client_metrics.csv"]:
        path = os.path.join(project_dir, f)
        if os.path.exists(path):
            os.remove(path)

    # ---- Start client (runs through all 3 phases) ----
    # count=0 means infinite; we'll kill it at the end
    print(f"\n[*] Starting normal client (interval={args.client_interval}ms)...")
    client_proc = subprocess.Popen(
        ["taskset", "-c", "0-3", client_bin, server_ip, str(args.client_interval), "0"],
        cwd=project_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[+] Client running (PID {client_proc.pid})")
    time.sleep(1)

    # ==============================
    # PHASE 1: BASELINE (no attack)
    # ==============================
    print(f"\n{'='*50}")
    print(f"  PHASE 1: BASELINE ({baseline_dur}s)")
    print(f"{'='*50}")
    print(f"  Client connecting alone — no bots active")
    try:
        time.sleep(baseline_dur)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        _cleanup(client_proc, [], project_dir)
        return

    # ==============================
    # PHASE 2: ATTACK
    # ==============================
    print(f"\n{'='*50}")
    print(f"  PHASE 2: DDOS ATTACK ({attack_dur}s)")
    print(f"{'='*50}")
    print(f"  Launching {args.bots} bot(s) with {args.threads} threads each...")

    bot_procs = []
    for i in range(args.bots):
        proc = subprocess.Popen(
            ["taskset", "-c", "4-11", bot_bin, str(args.threads), str(args.mode), server_ip],
            cwd=project_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        bot_procs.append(proc)
        print(f"    [+] bot{i} (PID {proc.pid}) -> {server_ip}")

    try:
        time.sleep(attack_dur)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        _cleanup(client_proc, bot_procs, project_dir)
        return

    # ==============================
    # PHASE 3: RECOVERY
    # ==============================
    print(f"\n{'='*50}")
    print(f"  PHASE 3: RECOVERY ({recovery_dur}s)")
    print(f"{'='*50}")
    print(f"  Killing all bots...")

    for proc in bot_procs:
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    # Also kill any lingering bot child processes
    subprocess.run(["pkill", "-f", "./bot"], stderr=subprocess.DEVNULL)

    try:
        time.sleep(recovery_dur)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")

    # ---- Collect results ----
    _cleanup(client_proc, [], project_dir)


def _cleanup(client_proc, bot_procs, project_dir):
    """Stop processes and print output file summary."""

    # Kill client
    try:
        os.kill(client_proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    time.sleep(1)

    # Kill any remaining bots
    for proc in bot_procs:
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    subprocess.run(["pkill", "-f", "./bot"], stderr=subprocess.DEVNULL)
    time.sleep(1)

    # ---- CSV files ----
    client_csv = os.path.join(project_dir, "client_metrics.csv")

    print(f"\n{'='*50}")
    print("  OUTPUT FILES")
    print(f"{'='*50}")
    if os.path.exists(client_csv):
        lines = sum(1 for _ in open(client_csv)) - 1
        print(f"  client_metrics.csv: {lines} data rows")
    else:
        print(f"  client_metrics.csv: not found")

    print(f"{'='*50}")
    print("\n[*] Experiment complete.")


def main():
    parser = argparse.ArgumentParser(
        description="PQC TLS DDoS experiment — bare-metal (no Mininet)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack.py --server-ip 192.168.1.100 --bots 5 --threads 10 --duration 60
  python3 attack.py --server-ip 10.0.0.1 --bots 3 --threads 20 --duration 45
        """,
    )

    parser.add_argument("--server-ip", type=str, required=True,
                        help="IP address of the remote PQC TLS server")
    parser.add_argument("--bots", type=int, default=5,
                        help="Number of bot processes (default: 5)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Threads per bot (default: 10)")
    parser.add_argument("--mode", type=int, default=1, choices=[1, 2],
                        help="Attack mode: 1=full handshake, 2=partial (default: 1)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Total experiment duration in seconds (default: 60)")
    parser.add_argument("--client-interval", type=int, default=500,
                        help="Client handshake interval in ms (default: 500)")

    args = parser.parse_args()

    if args.duration < 9:
        print("[!] Duration must be at least 9 seconds (3s per phase minimum)")
        sys.exit(1)

    run_experiment(args)


if __name__ == "__main__":
    main()
