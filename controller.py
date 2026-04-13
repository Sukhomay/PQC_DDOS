#!/usr/bin/env python3
"""
Mininet-based test harness for PQC TLS DDoS experiments.

Creates a virtual network with one server host and N bot hosts,
applies traffic shaping (bandwidth, delay, loss), runs the attack
for a specified duration, and collects metrics.

Usage:
    sudo python3 controller.py --bots 5 --threads 10 --duration 30
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
    """Star topology: 1 server + N bots connected through a single switch."""

    def build(self, n_bots=5, bw=None, delay=None, loss=None):
        switch = self.addSwitch("s1")

        # Server host
        self.addHost("server")
        link_opts = {}
        if bw is not None:
            link_opts["bw"] = bw
        if delay is not None:
            link_opts["delay"] = delay
        if loss is not None:
            link_opts["loss"] = loss

        self.addLink("server", switch, **link_opts)

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
    server_bin = os.path.join(project_dir, "server")
    bot_bin = os.path.join(project_dir, "bot")

    # Validate binaries exist
    for path, name in [(server_bin, "server"), (bot_bin, "bot")]:
        if not os.path.isfile(path):
            print(f"[!] Binary '{name}' not found at {path}")
            print(f"    Run 'make pqc-gen && make pqc-all' first.")
            sys.exit(1)

    setLogLevel("info")

    print("=" * 50)
    print("  PQC TLS DDoS Experiment")
    print("=" * 50)
    print(f"  Bots           : {args.bots}")
    print(f"  Threads/bot    : {args.threads}")
    print(f"  Attack mode    : {args.mode}")
    print(f"  Duration       : {args.duration}s")
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

    # Set switch to standalone (learning) mode — no SDN controller needed
    for s in net.switches:
        s.cmd("ovs-vsctl set-fail-mode", s.name, "standalone")

    server_host = net.get("server")
    server_ip = server_host.IP()

    print(f"\n[*] Server IP: {server_ip}")

    # Remove stale metrics file
    metrics_csv = os.path.join(project_dir, "metrics.csv")
    if os.path.exists(metrics_csv):
        os.remove(metrics_csv)

    # ---- Start server ----
    print("[*] Starting PQC TLS server...")
    server_host.cmd(f"cd {project_dir} && taskset -c 0-3 ./server > /tmp/pqc_server.log 2>&1 &")
    time.sleep(2)

    # Verify server started
    pid = server_host.cmd("pgrep -f './server'").strip()
    if not pid:
        print("[!] Server failed to start. Check /tmp/pqc_server.log")
        net.stop()
        sys.exit(1)
    print(f"[+] Server running (PID {pid})")

    # ---- Interactive mode ----
    if args.interactive:
        print("\n[*] Dropping into Mininet CLI. Use 'pingall' to test, 'exit' to quit.")
        print(f"    To manually launch bot: bot0 {bot_bin} {args.threads} {args.mode} {server_ip} &")
        CLI(net)
        server_host.cmd("kill %./server 2>/dev/null")
        net.stop()
        return

    # ---- Launch bots ----
    print(f"\n[*] Launching {args.bots} bot(s) with {args.threads} threads each...")
    for i in range(args.bots):
        bot_host = net.get(f"bot{i}")
        bot_host.cmd(
            f"cd {project_dir} && taskset -c 4-11 ./bot {args.threads} {args.mode} {server_ip} "
            f"> /tmp/pqc_bot{i}.log 2>&1 &"
        )
        # print(f"    [+] bot{i} ({bot_host.IP()}) -> {server_ip}")

    # ---- Wait for attack duration ----
    print(f"\n[*] Attack running for {args.duration} seconds...")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    # ---- Stop bots ----
    print("\n[*] Stopping bots...")
    for i in range(args.bots):
        bot_host = net.get(f"bot{i}")
        bot_host.cmd("pkill -f './bot' 2>/dev/null")

    time.sleep(1)

    # ---- Collect server metrics ----
    print("[*] Collecting server metrics...")

    server_log = ""
    try:
        with open("/tmp/pqc_server.log", "r") as f:
            server_log = f.read()
    except FileNotFoundError:
        pass

    # Parse last metrics block from server log
    blocks = server_log.split("====== SERVER METRICS ======")
    if len(blocks) >= 2:
        last_block = blocks[-1]
        print("\n" + "=" * 50)
        print("  FINAL SERVER METRICS")
        print("=" * 50)
        for line in last_block.strip().split("\n"):
            line = line.strip()
            if line and "====" not in line:
                print(f"  {line}")
        print("=" * 50)
    else:
        print("[!] No metrics captured from server log")

    # Print CSV metrics file if it exists
    if os.path.exists(metrics_csv):
        print(f"\n[+] CSV metrics saved to: {metrics_csv}")

    # ---- Stop server ----
    server_host.cmd("pkill -f './server' 2>/dev/null")
    time.sleep(1)

    # ---- Cleanup ----
    net.stop()
    print("\n[*] Experiment complete.")


# ========================== #
#           MAIN             #
# ========================== #
def main():
    parser = argparse.ArgumentParser(
        description="PQC TLS DDoS experiment using Mininet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 controller.py --bots 5 --threads 10 --duration 30
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
    parser.add_argument("--duration", type=int, default=30,
                        help="Attack duration in seconds (default: 30)")
    parser.add_argument("--bw", type=float, default=None,
                        help="Link bandwidth in Mbps (default: unlimited)")
    parser.add_argument("--delay", type=str, default=None,
                        help="Link delay, e.g. '20ms' (default: none)")
    parser.add_argument("--loss", type=float, default=None,
                        help="Packet loss percentage (default: 0)")
    parser.add_argument("--interactive", action="store_true",
                        help="Drop into Mininet CLI instead of auto-run")

    args = parser.parse_args()
    run_experiment(args)


if __name__ == "__main__":
    main()