#!/usr/bin/env python3
"""
Incremental DDoS stress test for PQC TLS servers.

Ramps up DDoS load in rounds until the server can no longer serve
the legitimate client (denial of service achieved).

Each round:
  1. Launch bots with current thread count
  2. Wait for load to saturate
  3. Run a probe client with N handshakes
  4. Analyze success/fail from client_metrics.csv
  5. Kill bots, record results
  6. If failure threshold exceeded → stop

Output: stress_results.csv with one row per round.

Usage:
    python3 stress_test.py --server-ip 192.168.1.100
    python3 stress_test.py --server-ip 10.0.0.1 --bots 5 --start-threads 5 --max-threads 200
"""

import argparse
import csv
import os
import signal
import subprocess
import sys
import time


def kill_all_bots(bot_procs):
    """Kill all bot processes."""
    for proc in bot_procs:
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    subprocess.run(["pkill", "-f", "./bot"], stderr=subprocess.DEVNULL)
    time.sleep(2)


def parse_client_metrics(csv_path):
    """Parse client_metrics.csv and return (success_count, fail_count, avg_cycles)."""
    success = 0
    fail = 0
    total_cycles = 0

    try:
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["status"] == "success":
                    success += 1
                    total_cycles += int(row["handshake_cycles"])
                else:
                    fail += 1
    except FileNotFoundError:
        return 0, 0, 0

    avg_cycles = total_cycles // success if success > 0 else 0
    return success, fail, avg_cycles


def run_stress_test(args):
    project_dir = os.path.dirname(os.path.abspath(__file__))
    bot_bin = os.path.join(project_dir, "bot")
    client_bin = os.path.join(project_dir, "pqc_client")
    client_csv = os.path.join(project_dir, "client_metrics.csv")
    results_csv = os.path.join(project_dir, "stress_results.csv")

    # Validate binaries
    for path, name in [(bot_bin, "bot"), (client_bin, "pqc_client")]:
        if not os.path.isfile(path):
            print(f"[!] Binary '{name}' not found at {path}")
            print(f"    Run 'make pqc-all' first.")
            sys.exit(1)

    server_ip = args.server_ip

    print("=" * 60)
    print("  PQC TLS DDoS Stress Test (Incremental)")
    print("=" * 60)
    print(f"  Server IP         : {server_ip}")
    print(f"  Bots              : {args.bots}")
    print(f"  Start threads/bot : {args.start_threads}")
    print(f"  Max threads/bot   : {args.max_threads}")
    print(f"  Round duration    : {args.round_duration}s")
    print(f"  Probe handshakes  : {args.probe_count}")
    print(f"  Failure threshold : {args.failure_threshold * 100:.0f}%")
    print(f"  Warmup            : {args.warmup}s")
    print(f"  Cooldown          : {args.cooldown}s")
    print("=" * 60)

    # ---- Baseline round (no bots) ----
    print(f"\n{'='*60}")
    print(f"  ROUND 0: BASELINE (no bots)")
    print(f"{'='*60}")

    # Remove stale CSV
    if os.path.exists(client_csv):
        os.remove(client_csv)

    # Run probe client
    probe_proc = subprocess.run(
        ["taskset", "-c", "0-3", client_bin, server_ip, "0", str(args.probe_count)],
        cwd=project_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=args.round_duration + 30,
    )

    baseline_success, baseline_fail, baseline_avg = parse_client_metrics(client_csv)
    baseline_total = baseline_success + baseline_fail
    baseline_fail_rate = baseline_fail / baseline_total if baseline_total > 0 else 0

    print(f"  Success: {baseline_success} | Fail: {baseline_fail} | "
          f"Failure rate: {baseline_fail_rate*100:.1f}% | Avg cycles: {baseline_avg}")

    if baseline_success == 0:
        print("\n[!] Baseline failed — server not reachable. Aborting.")
        sys.exit(1)

    # ---- Open results CSV ----
    results_file = open(results_csv, "w")
    results_writer = csv.writer(results_file)
    results_writer.writerow([
        "round", "threads_per_bot", "total_attackers",
        "probe_success", "probe_fail", "failure_rate",
        "avg_handshake_cycles"
    ])
    # Write baseline
    results_writer.writerow([
        0, 0, 0,
        baseline_success, baseline_fail, f"{baseline_fail_rate:.4f}",
        baseline_avg
    ])
    results_file.flush()

    # ---- Incremental rounds ----
    threads_per_bot = args.start_threads
    round_num = 0
    breaking_point = None

    while threads_per_bot <= args.max_threads:
        round_num += 1
        total_attackers = args.bots * threads_per_bot

        print(f"\n{'='*60}")
        print(f"  ROUND {round_num}: {args.bots} bots × {threads_per_bot} threads "
              f"= {total_attackers} attackers")
        print(f"{'='*60}")

        # Launch bots
        print(f"  Launching bots...")
        bot_procs = []
        for i in range(args.bots):
            proc = subprocess.Popen(
                ["taskset", "-c", "4-11", bot_bin,
                 str(threads_per_bot), str(args.mode), server_ip],
                cwd=project_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            bot_procs.append(proc)

        # Warmup — let the attack saturate
        print(f"  Warmup ({args.warmup}s)...")
        time.sleep(args.warmup)

        # Run probe client
        print(f"  Running probe ({args.probe_count} handshakes)...")
        if os.path.exists(client_csv):
            os.remove(client_csv)

        try:
            subprocess.run(
                ["taskset", "-c", "0-3", client_bin, server_ip, "0",
                 str(args.probe_count)],
                cwd=project_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=args.round_duration + 30,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] Probe timed out — server overwhelmed")

        # Parse results
        success, fail, avg_cycles = parse_client_metrics(client_csv)
        total = success + fail
        fail_rate = fail / total if total > 0 else 1.0

        # If probe produced no results at all, that's a complete failure
        if total == 0:
            fail_rate = 1.0

        print(f"  Success: {success} | Fail: {fail} | "
              f"Failure rate: {fail_rate*100:.1f}% | Avg cycles: {avg_cycles}")

        # Record results
        results_writer.writerow([
            round_num, threads_per_bot, total_attackers,
            success, fail, f"{fail_rate:.4f}",
            avg_cycles
        ])
        results_file.flush()

        # Kill bots
        print(f"  Killing bots...")
        kill_all_bots(bot_procs)

        # Check failure threshold
        if fail_rate >= args.failure_threshold:
            breaking_point = (round_num, threads_per_bot, total_attackers, fail_rate)
            print(f"\n  >>> FAILURE THRESHOLD REACHED <<<")
            print(f"  >>> Server denied at {total_attackers} attackers "
                  f"({args.bots} bots × {threads_per_bot} threads)")
            break

        # Cooldown before next round
        print(f"  Cooldown ({args.cooldown}s)...")
        time.sleep(args.cooldown)

        # Increase load for next round
        threads_per_bot *= 2

    results_file.close()

    # ---- Summary ----
    print(f"\n{'='*60}")
    print(f"  STRESS TEST COMPLETE")
    print(f"{'='*60}")
    if breaking_point:
        rnd, tpb, total, fr = breaking_point
        print(f"  Server denied at round {rnd}")
        print(f"  Breaking point   : {total} attackers "
              f"({args.bots} bots × {tpb} threads)")
        print(f"  Failure rate     : {fr*100:.1f}%")
    else:
        print(f"  Server survived all rounds up to "
              f"{args.bots} × {args.max_threads} = "
              f"{args.bots * args.max_threads} attackers")
    print(f"  Results saved to : {results_csv}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Incremental DDoS stress test for PQC TLS servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 stress_test.py --server-ip 192.168.1.100
  python3 stress_test.py --server-ip 10.0.0.1 --bots 5 --start-threads 5 --max-threads 200
  python3 stress_test.py --server-ip 10.0.0.1 --failure-threshold 0.5
        """,
    )

    parser.add_argument("--server-ip", type=str, required=True,
                        help="IP of the remote PQC TLS server")
    parser.add_argument("--bots", type=int, default=5,
                        help="Number of bot processes (default: 5)")
    parser.add_argument("--start-threads", type=int, default=5,
                        help="Starting threads per bot (default: 5)")
    parser.add_argument("--max-threads", type=int, default=200,
                        help="Max threads per bot (default: 200)")
    parser.add_argument("--mode", type=int, default=1, choices=[1, 2],
                        help="Attack mode: 1=full handshake, 2=partial (default: 1)")
    parser.add_argument("--round-duration", type=int, default=15,
                        help="Max seconds per probe round (default: 15)")
    parser.add_argument("--probe-count", type=int, default=20,
                        help="Handshakes per probe (default: 20)")
    parser.add_argument("--failure-threshold", type=float, default=0.8,
                        help="Failure rate to declare DoS (default: 0.8)")
    parser.add_argument("--warmup", type=int, default=5,
                        help="Warmup seconds before probing (default: 5)")
    parser.add_argument("--cooldown", type=int, default=3,
                        help="Cooldown seconds between rounds (default: 3)")

    args = parser.parse_args()
    run_stress_test(args)


if __name__ == "__main__":
    main()
