#!/usr/bin/env python3
"""
Mininet-based test harness for PQC TLS DDoS experiments.

Orchestrates a 3-phase experiment:
  1. Pre-attack baseline:  Client connects alone
  2. Attack phase:         Bots launched, client continues during DDoS
  3. Post-attack recovery: Bots killed, client continues

Usage:
    sudo python3 controller.py --bots 5 --threads 10 --duration 60
    sudo python3 controller.py --bots 3 --delay 50ms --bw 100 --loss 1
    sudo python3 controller.py --interactive --bots 2
"""

import argparse
import os
import sys
import time

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel


# ========================== #
#         TOPOLOGY           #
# ========================== #
class AttackTopo(Topo):
    """Star topology: 1 server + 1 client + N bots through a single switch."""

    def build(self, n_bots=5, bw=None, delay=None, loss=None):
        switch = self.addSwitch("s1")

        link_opts = {}
        if bw is not None:
            link_opts["bw"] = bw
        if delay is not None:
            link_opts["delay"] = delay
        if loss is not None:
            link_opts["loss"] = loss

        # Server host
        self.addHost("server")
        self.addLink("server", switch, **link_opts)

        # Normal client host
        self.addHost("client")
        self.addLink("client", switch, **link_opts)

        # Bot hosts
        for i in range(n_bots):
            name = f"bot{i}"
            self.addHost(name)
            self.addLink(name, switch, **link_opts)


# ========================== #
#       EXPERIMENT RUNNER    #
# ========================== #
def run_experiment(args):
    project_dir = os.path.dirname(os.path.abspath(__file__))
    server_bin = os.path.join(project_dir, "pqc_server")
    bot_bin = os.path.join(project_dir, "bot")
    client_bin = os.path.join(project_dir, "pqc_client")

    # Validate binaries exist
    for path, name in [(server_bin, "pqc_server"), (bot_bin, "bot"), (client_bin, "pqc_client")]:
        if not os.path.isfile(path):
            print(f"[!] Binary '{name}' not found at {path}")
            print(f"    Run 'make pqc-all' first.")
            sys.exit(1)

    setLogLevel("info")

    # Phase durations
    phase_duration = args.duration // 3
    baseline_dur = phase_duration
    attack_dur = phase_duration
    recovery_dur = args.duration - 2 * phase_duration  # absorb remainder

    print("=" * 50)
    print("  PQC TLS DDoS Experiment (3-Phase)")
    print("=" * 50)
    print(f"  Bots           : {args.bots}")
    print(f"  Threads/bot    : {args.threads}")
    print(f"  Attack mode    : {args.mode}")
    print(f"  Total duration : {args.duration}s")
    print(f"    Phase 1 (baseline)  : {baseline_dur}s")
    print(f"    Phase 2 (attack)    : {attack_dur}s")
    print(f"    Phase 3 (recovery)  : {recovery_dur}s")
    print(f"  Client interval: {args.client_interval}ms")
    print(f"  Bandwidth      : {args.bw or 'unlimited'} Mbps")
    print(f"  Delay          : {args.delay or 'none'}")
    print(f"  Packet loss    : {args.loss or 0}%")
    print("=" * 50)

    # Build topology
    topo = AttackTopo(
        n_bots=args.bots,
        bw=args.bw,
        delay=args.delay,
        loss=args.loss,
    )

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
    )

    net.start()

    # Set switch to standalone (learning) mode
    for s in net.switches:
        s.cmd("ovs-vsctl set-fail-mode", s.name, "standalone")

    server_host = net.get("server")
    client_host = net.get("client")
    server_ip = server_host.IP()

    print(f"\n[*] Server IP : {server_ip}")
    print(f"[*] Client IP : {client_host.IP()}")

    # Remove stale metrics files
    for f in ["metrics.csv", "client_metrics.csv"]:
        path = os.path.join(project_dir, f)
        if os.path.exists(path):
            os.remove(path)

    # ---- Start server ----
    print("\n[*] Starting PQC TLS server...")
    server_host.cmd(f"cd {project_dir} && taskset -c 0-3 ./pqc_server > /dev/null 2>&1 &")
    time.sleep(2)

    pid = server_host.cmd("pgrep -f './pqc_server'").strip()
    if not pid:
        print("[!] Server failed to start. Check /tmp/pqc_server.log")
        net.stop()
        sys.exit(1)
    print(f"[+] Server running (PID {pid})")

    # ---- Interactive mode ----
    if args.interactive:
        print("\n[*] Dropping into Mininet CLI.")
        print(f"    Server: {server_ip}")
        print(f"    Client: client {client_bin} {server_ip} {args.client_interval} 10")
        print(f"    Bot:    bot0 {bot_bin} {args.threads} {args.mode} {server_ip}")
        CLI(net)
        server_host.cmd("kill %./pqc_server 2>/dev/null")
        net.stop()
        return

    # ---- Start client (runs through all 3 phases) ----
    # count=0 means infinite; we'll kill it at the end
    print(f"\n[*] Starting normal client (interval={args.client_interval}ms)...")
    client_host.cmd(
        f"cd {project_dir} && taskset -c 4 ./pqc_client {server_ip} {args.client_interval} 0 "
        f"> /dev/null 2>&1 &"
    )
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
        _cleanup(net, server_host, client_host, project_dir)
        return

    # ==============================
    # PHASE 2: ATTACK
    # ==============================
    print(f"\n{'='*50}")
    print(f"  PHASE 2: DDOS ATTACK ({attack_dur}s)")
    print(f"{'='*50}")
    print(f"  Launching {args.bots} bot(s) with {args.threads} threads each...")

    for i in range(args.bots):
        bot_host = net.get(f"bot{i}")
        bot_host.cmd(
            f"cd {project_dir} && taskset -c 5-11 ./bot {args.threads} {args.mode} {server_ip} > /dev/null 2>&1 &"
        )
        print(f"    [+] bot{i} ({bot_host.IP()}) -> {server_ip}")

    try:
        time.sleep(attack_dur)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        _cleanup(net, server_host, client_host, project_dir)
        return

    # ==============================
    # PHASE 3: RECOVERY
    # ==============================
    print(f"\n{'='*50}")
    print(f"  PHASE 3: RECOVERY ({recovery_dur}s)")
    print(f"{'='*50}")
    print(f"  Killing all bots...")

    for i in range(args.bots):
        bot_host = net.get(f"bot{i}")
        bot_host.cmd("pkill -f './bot' 2>/dev/null")

    try:
        time.sleep(recovery_dur)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")

    # ---- Collect results ----
    _cleanup(net, server_host, client_host, project_dir)


def _cleanup(net, server_host, client_host, project_dir):
    """Stop processes, print metrics, and tear down network."""

    # Kill client and server
    client_host.cmd("pkill -f './pqc_client' 2>/dev/null")
    time.sleep(1)
    server_host.cmd("pkill -f './pqc_server' 2>/dev/null")
    time.sleep(1)

    # Metrics are logged directly by pqc_server -> metrics.csv
    # and pqc_client -> client_metrics.csv.  No log-file parsing needed.

    # ---- CSV files ----
    metrics_csv = os.path.join(project_dir, "metrics.csv")
    client_csv = os.path.join(project_dir, "client_metrics.csv")

    print(f"\n{'='*50}")
    print("  OUTPUT FILES")
    print(f"{'='*50}")
    for path in [metrics_csv, client_csv]:
        if os.path.exists(path):
            lines = sum(1 for _ in open(path)) - 1  # subtract header
            print(f"  {os.path.basename(path)}: {lines} data rows")
        else:
            print(f"  {os.path.basename(path)}: not found")

    print(f"{'='*50}")

    net.stop()
    print("\n[*] Experiment complete.")


# ========================== #
#           MAIN             #
# ========================== #
def main():
    parser = argparse.ArgumentParser(
        description="PQC TLS DDoS experiment using Mininet (3-phase)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 controller.py --bots 5 --threads 10 --duration 60
  sudo python3 controller.py --bots 3 --delay 50ms --bw 100 --loss 1
  sudo python3 controller.py --interactive --bots 2
        """,
    )

    parser.add_argument("--bots", type=int, default=5,
                        help="Number of bot hosts (default: 5)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Threads per bot (default: 10)")
    parser.add_argument("--mode", type=int, default=1, choices=[1, 2],
                        help="Attack mode: 1=full handshake, 2=partial (default: 1)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Total experiment duration in seconds (default: 60)")
    parser.add_argument("--client-interval", type=int, default=500,
                        help="Client handshake interval in ms (default: 500)")
    parser.add_argument("--bw", type=float, default=None,
                        help="Link bandwidth in Mbps (default: unlimited)")
    parser.add_argument("--delay", type=str, default=None,
                        help="Link delay, e.g. '20ms' (default: none)")
    parser.add_argument("--loss", type=float, default=None,
                        help="Packet loss percentage (default: 0)")
    parser.add_argument("--interactive", action="store_true",
                        help="Drop into Mininet CLI instead of auto-run")

    args = parser.parse_args()

    if args.duration < 9:
        print("[!] Duration must be at least 9 seconds (3s per phase minimum)")
        sys.exit(1)

    run_experiment(args)


if __name__ == "__main__":
    main()