#!/usr/bin/env python3
"""
Extrapolate incomplete stress test results and generate comparison plots.

Uses exponential growth model on the observed failure rate data points
to estimate the breaking point for algorithms that hit OS thread limits.
"""

import numpy as np
import matplotlib.pyplot as plt
import os

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(PROJECT_DIR, "stress_test_results")

# ============================================================
# Observed data from logs: (total_attackers, failure_rate)
# ============================================================

algos = {
    "SecP384r1+MLKEM768": {
        "failure": [(100, 0.00), (200, 0.00), (400, 0.00), (800, 0.00),
                    (1600, 0.04), (3200, 0.54), (6400, 0.90)],
        "cycles":  [(100, 428651082), (200, 1420831844), (400, 3011648891),
                    (800, 5974077835), (1600, 9780049230), (3200, 12862380907),
                    (6400, 14591741663)],
        "baseline_cycles": 65313910,
        "breaking_point": 6400,
        "complete": True,
    },
    "SecP521r1+MLKEM1024": {
        "failure": [(100, 0.00), (200, 0.00), (400, 0.00), (800, 0.00),
                    (1600, 0.35), (3200, 0.90)],
        "cycles":  [(100, 486047149), (200, 1278501105), (400, 2466073897),
                    (800, 6205094899), (1600, 9776119661), (3200, 16388018477)],
        "baseline_cycles": 71571483,
        "breaking_point": 3200,
        "complete": True,
    },
    "MLKEM-768": {
        # Only use clean data (rounds 5-6; rounds 7-9 had bot launch anomalies)
        "failure": [(400, 0.00), (800, 0.00), (1600, 0.00), (3200, 0.00),
                    (6400, 0.01), (12800, 0.11)],
        "cycles":  [(400, 3794030), (800, 3858271), (1600, 4108875),
                    (3200, 4049333), (6400, 618171981), (12800, 1072975583)],
        "baseline_cycles": 4757678,
        "cost_weight": 1.0,
        "breaking_point": None,
        "complete": False,
    },
    "MLKEM-1024": {
        "failure": [(200, 0.00), (400, 0.00), (800, 0.00), (1600, 0.00),
                    (3200, 0.00), (6400, 0.01), (12800, 0.12)],
        "cycles":  [(200, 88341971), (400, 172426346), (800, 354868365),
                    (1600, 453401169), (3200, 569892070), (6400, 732303588),
                    (12800, 915020998)],
        "baseline_cycles": 8975790,
        "cost_weight": 1.3,   # heavier KEM → server degrades faster
        "breaking_point": None,
        "complete": False,
    },
    "X25519": {
        "failure": [(400, 0.00), (800, 0.00), (1600, 0.00), (3200, 0.00),
                    (6400, 0.00), (12800, 0.01)],
        "cycles":  [(400, 36182932), (800, 62296118), (1600, 174809606),
                    (3200, 214527786), (6400, 301955725), (12800, 397657990)],
        "baseline_cycles": 4506210,
        "cost_weight": 1.0,
        "breaking_point": None,
        "complete": False,
    },
}


# ============================================================
# Exponential extrapolation of failure rate
# ============================================================

def extrapolate_exp(failure_data, cost_weight=1.0, threshold=0.80):
    """
    Fit f(x) = a * exp(b * x) using the last two data points with
    non-zero failure rates. cost_weight scales the growth rate to
    account for heavier crypto (higher weight = fails sooner).
    """
    # Get points with non-zero failure
    fail_pts = [(x, f) for x, f in failure_data if f > 0]

    if len(fail_pts) >= 2:
        # Use last two failure points
        (x1, f1), (x2, f2) = fail_pts[-2], fail_pts[-1]
    elif len(fail_pts) == 1:
        # Only one failure point — use the last zero-failure point as anchor
        (x2, f2) = fail_pts[0]
        zero_pts = [(x, f) for x, f in failure_data if f == 0]
        if zero_pts:
            x1 = zero_pts[-1][0]
            f1 = 0.001  # treat 0% as ~0.1% for fitting
        else:
            return None
    else:
        return None

    # Solve for b: f2/f1 = exp(b * (x2 - x1))
    if f1 <= 0:
        f1 = 0.001
    b = np.log(f2 / f1) / (x2 - x1)
    b *= cost_weight  # heavier crypto → faster degradation
    a = f1 / np.exp(b * x1)

    # Find where a * exp(b * x) = threshold
    if a <= 0 or b <= 0:
        return None
    x_break = np.log(threshold / a) / b
    # Return as a multiple of 40 (since bots are fixed to 40)
    return int(round(x_break / 40.0) * 40)


print("=" * 60)
print("  Stress Test — Breaking Point Extrapolation")
print("=" * 60)

for name, algo in algos.items():
    if algo["complete"]:
        print(f"\n  {name}")
        print(f"    Breaking point (observed): {algo['breaking_point']:,} attackers")
    else:
        bp = extrapolate_exp(algo["failure"], cost_weight=algo.get("cost_weight", 1.0))
        algo["breaking_point"] = bp
        print(f"\n  {name}")
        if bp:
            print(f"    Breaking point (extrapolated): ~{bp:,} attackers")
        else:
            print(f"    Could not extrapolate")

print(f"\n{'='*60}")


# ============================================================
# Plot 1: Failure Rate vs Attackers
# ============================================================
colors = {
    "SecP384r1+MLKEM768":  "#e74c3c",
    "SecP521r1+MLKEM1024": "#e67e22",
    "MLKEM-768":           "#2ecc71",
    "MLKEM-1024":          "#3498db",
    "X25519":              "#9b59b6",
}

fig, axes = plt.subplots(1, 2, figsize=(18, 7))

ax1 = axes[0]
for name, algo in algos.items():
    x = [d[0] for d in algo["failure"]]
    y = [d[1] * 100 for d in algo["failure"]]
    style = '-o' if algo["complete"] else '--s'
    ax1.plot(x, y, style, color=colors[name], label=name, linewidth=2, markersize=6)

    # Show extrapolated point
    if not algo["complete"] and algo["breaking_point"]:
        bp = algo["breaking_point"]
        ax1.plot(bp, 80, '*', color=colors[name],
                 markersize=15, markeredgecolor='black', markeredgewidth=1)
        # Connect last point to extrapolated point
        ax1.plot([x[-1], bp], [y[-1], 80], ':', color=colors[name], alpha=0.7)
        # Annotate the text value next to the star
        ax1.annotate(f'~{bp:,}', xy=(bp, 80), xytext=(5, -15), textcoords='offset points',
                     color=colors[name], fontsize=10, fontweight='bold')
    elif algo["complete"] and algo["breaking_point"]:
        bp = algo["breaking_point"]
        # Annotate observed breaking point
        ax1.annotate(f'{bp:,}', xy=(bp, 80), xytext=(5, -15), textcoords='offset points',
                     color=colors[name], fontsize=10, fontweight='bold')

ax1.axhline(y=80, color='red', linestyle=':', alpha=0.4, label='Threshold (80%)')
ax1.set_xlabel('Total Attackers', fontsize=12)
ax1.set_ylabel('Failure Rate (%)', fontsize=12)
ax1.set_title('Client Failure Rate vs DDoS Load', fontsize=14, fontweight='bold')
ax1.legend(fontsize=9, loc='upper left')
ax1.grid(True, alpha=0.3)
ax1.set_xscale('log')

# ============================================================
# Plot 2: Avg Handshake Cycles vs Attackers
# ============================================================
ax2 = axes[1]
for name, algo in algos.items():
    x = [d[0] for d in algo["cycles"]]
    y = [d[1] for d in algo["cycles"]]
    style = '-o' if algo["complete"] else '--s'
    ax2.plot(x, y, style, color=colors[name], label=name, linewidth=2, markersize=6)

ax2.set_xlabel('Total Attackers', fontsize=12)
ax2.set_ylabel('Avg Handshake Cycles', fontsize=12)
ax2.set_title('Handshake Latency Under DDoS', fontsize=14, fontweight='bold')
ax2.legend(fontsize=9, loc='upper left')
ax2.grid(True, alpha=0.3)
ax2.set_xscale('log')
ax2.set_yscale('log')

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "stress_comparison.png"), dpi=150)
print(f"\nSaved: stress_comparison.png")


# ============================================================
# Plot 3: Breaking Point Bar Chart
# ============================================================
fig2, ax3 = plt.subplots(figsize=(10, 6))

bar_data = []
for name, algo in algos.items():
    bp = algo["breaking_point"]
    if bp:
        bar_data.append((name, bp, not algo["complete"]))

bar_data.sort(key=lambda x: x[1])

labels = [d[0] for d in bar_data]
values = [d[1] for d in bar_data]
estimated = [d[2] for d in bar_data]
bar_colors = [colors[l] for l in labels]

bars = ax3.barh(labels, values, color=bar_colors, edgecolor='black', height=0.5)
for bar, hatch, est in zip(bars, estimated, estimated):
    if est:
        bar.set_hatch('///')
        bar.set_edgecolor('gray')

for bar, val in zip(bars, values):
    ax3.text(bar.get_width() + max(values) * 0.02,
             bar.get_y() + bar.get_height() / 2,
             f'{val:,}', va='center', fontsize=11, fontweight='bold')

ax3.set_xlabel('Attackers at Breaking Point (80% failure rate)', fontsize=12)
ax3.set_title('DDoS Resilience — Breaking Point Comparison',
              fontsize=14, fontweight='bold')
ax3.grid(True, alpha=0.3, axis='x')

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "breaking_point_comparison.png"), dpi=150)
print(f"Saved: breaking_point_comparison.png")
