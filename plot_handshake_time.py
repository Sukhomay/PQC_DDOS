#!/usr/bin/env python3
"""
Plot average handshake cycles over time for all algorithms
using server-side metrics CSVs from stress_test_results/.
"""

import csv
import os
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stress_test_results")

# Algorithm configs: csv filename → display name + color
algo_configs = {
    "p521_mlkem1024_metrics.csv": {
        "name": "SecP521r1 + MLKEM-1024 (Hybrid)",
        "color": "#e74c3c",
        "linewidth": 2.5,
    },
    "p384_mlkem768_metrics.csv": {
        "name": "SecP384r1 + MLKEM-768 (Hybrid)",
        "color": "#e67e22",
        "linewidth": 2.5,
    },
    "mlkem1024_metrics.csv": {
        "name": "MLKEM-1024 (Pure PQC)",
        "color": "#3498db",
        "linewidth": 2,
    },
    "mlkem768_metrics.csv": {
        "name": "MLKEM-768 (Pure PQC)",
        "color": "#2ecc71",
        "linewidth": 2,
    },
    "X25519_metrics.csv": {
        "name": "X25519 (Classical)",
        "color": "#9b59b6",
        "linewidth": 2,
    },
}


def load_metrics(csv_path):
    """Load metrics CSV and return filtered (relative_time, avg_cycles) arrays."""
    timestamps = []
    avg_cycles = []

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = int(row["timestamp"])
            ac = int(row["active_connections"])
            cycles = int(row["avg_handshake_cycles"])
            success = int(row["successful_handshakes"])

            # Only include rows where server is actively handling handshakes
            if cycles > 0 and success > 0:
                timestamps.append(ts)
                avg_cycles.append(cycles)

    if not timestamps:
        return np.array([]), np.array([])

    # Convert to relative time (seconds from first active entry)
    t0 = timestamps[0]
    rel_time = np.array([t - t0 for t in timestamps], dtype=float)
    avg_cycles = np.array(avg_cycles, dtype=float)

    return rel_time, avg_cycles


def smooth(y, window=5):
    """Simple moving average smoothing."""
    if len(y) < window:
        return y
    kernel = np.ones(window) / window
    # Pad edges to avoid shrinking
    padded = np.concatenate([np.full(window // 2, y[0]), y, np.full(window // 2, y[-1])])
    smoothed = np.convolve(padded, kernel, mode='valid')
    return smoothed[:len(y)]


# ============================================================
# Load all data
# ============================================================
all_data = {}
for filename, config in algo_configs.items():
    csv_path = os.path.join(RESULTS_DIR, filename)
    if os.path.exists(csv_path):
        t, c = load_metrics(csv_path)
        if len(t) > 0:
            all_data[filename] = {"time": t, "cycles": c, **config}
            print(f"  Loaded {filename}: {len(t)} points, "
                  f"max cycles = {c.max():.2e}, duration = {t[-1]:.0f}s")
        else:
            print(f"  [!] {filename}: no valid data points")
    else:
        print(f"  [!] {filename}: file not found")


# ============================================================
# Plot: Avg Handshake Cycles vs Time (all algorithms)
# ============================================================
fig, ax = plt.subplots(figsize=(14, 7))

# Sort by expected order: hybrids first (highest), then pure PQC, then classical
plot_order = [
    "p521_mlkem1024_metrics.csv",
    "p384_mlkem768_metrics.csv",
    "mlkem1024_metrics.csv",
    "mlkem768_metrics.csv",
    "X25519_metrics.csv",
]

for filename in plot_order:
    if filename not in all_data:
        continue

    d = all_data[filename]
    t = d["time"]
    c = d["cycles"]

    # Smooth to reduce noise
    c_smooth = smooth(c, window=5)

    ax.plot(t, c_smooth,
            color=d["color"],
            linewidth=d["linewidth"],
            label=d["name"],
            alpha=0.9)

ax.set_xlabel("Time (seconds from start)", fontsize=13)
ax.set_ylabel("Avg Handshake Cycles (server-side)", fontsize=13)
ax.set_title("Server Handshake Performance Under Incremental DDoS Load",
             fontsize=15, fontweight='bold')
ax.legend(fontsize=11, loc='upper left')
ax.grid(True, alpha=0.3)
ax.set_yscale('log')

# Add annotation
ax.annotate("Higher = worse performance",
            xy=(0.98, 0.98), xycoords='axes fraction',
            fontsize=10, ha='right', va='top',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', alpha=0.8))

plt.tight_layout()
output = os.path.join(RESULTS_DIR, "handshake_time_comparison.png")
plt.savefig(output, dpi=150)
print(f"\nSaved: {output}")
