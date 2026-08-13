import matplotlib.pyplot as plt
import numpy as np

np.random.seed(42)
t = np.arange(0, 46)

# ---------------------------------------------------------------------------
# Synthetic resource profiles for Mode 1 (Full Handshake Flood)
# ---------------------------------------------------------------------------
cpu_m1 = np.where(t < 15, 10 + np.random.normal(0, 1, len(t)),
         np.where(t < 30, 93 + np.random.normal(0, 2, len(t)),
                          12 + np.random.normal(0, 1, len(t))))

fd_m1 = np.where(t < 15, 20 + np.random.normal(0, 3, len(t)),
        np.where(t < 30, 350 + np.random.normal(0, 80, len(t)),
                         20 + np.random.normal(0, 3, len(t))))

mem_m1 = np.where(t < 15, 50 + np.random.normal(0, 3, len(t)),
         np.where(t < 30, 210 + np.random.normal(0, 20, len(t)),
                          50 + np.random.normal(0, 3, len(t))))

threads_m1 = np.where(t < 15, 4900 + np.random.normal(0, 10, len(t)),
             np.where(t < 30, 4550 + np.random.normal(0, 80, len(t)),
                              4900 + np.random.normal(0, 10, len(t))))

# ---------------------------------------------------------------------------
# Synthetic resource profiles for Mode 2 (Connection Holding / Slowloris)
# ---------------------------------------------------------------------------
def step_up(t, t_start, low, high, rise_seconds=2):
    out = np.full_like(t, low, dtype=float)
    for i, ti in enumerate(t):
        if ti >= t_start and ti < t_start + rise_seconds:
            frac = (ti - t_start) / rise_seconds
            out[i] = low + frac * (high - low)
        elif ti >= t_start + rise_seconds:
            out[i] = high
    return out

cpu_m2 = np.where(t < 15, 10 + np.random.normal(0, 1, len(t)),
         np.where(t == 15, 78,
         np.where(t == 16, 45,
                          12 + np.random.normal(0, 1, len(t)))))

fd_m2 = step_up(t, 15, 20, 4000, rise_seconds=3) + np.random.normal(0, 5, len(t))
fd_m2 = np.clip(fd_m2, 0, 4100)

mem_m2 = step_up(t, 15, 50, 1150, rise_seconds=3) + np.random.normal(0, 5, len(t))
mem_m2 = np.clip(mem_m2, 0, 1300)

threads_m2 = 5000 - step_up(t, 15, 100, 4000, rise_seconds=3) + np.random.normal(0, 10, len(t))
threads_m2 = np.clip(threads_m2, 0, 5000)

# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(2, 2, figsize=(14, 9), sharex=True)
fig.suptitle('Server Resource Profile: Full Handshake Flood (Mode 1) vs Connection-Holding (Mode 2)',
             fontsize=14, fontweight='bold', y=0.98)

panels = [
    (axes[0, 0], 'CPU Utilization (%)',       cpu_m1, cpu_m2, (0, 105)),
    (axes[0, 1], 'Open File Descriptors',     fd_m1,  fd_m2,  (0, 4800)),
    (axes[1, 0], 'Server Memory (MB)',         mem_m1, mem_m2, (0, 1400)),
    (axes[1, 1], 'Available Thread Pool',      threads_m1, threads_m2, (0, 5500)),
]

for ax, title, m1, m2, ylim in panels:
    # Attack window shading
    ax.axvspan(15, 30, alpha=0.07, color='red')

    ax.plot(t, m1, '-', color='#e74c3c', linewidth=2, label='Mode 1 (Full Flood)')
    ax.plot(t, m2, '--', color='#2980b9', linewidth=2, label='Mode 2 (Holding)')

    ax.axvline(x=15, color='red', linestyle=':', alpha=0.4)
    ax.axvline(x=30, color='green', linestyle=':', alpha=0.4)

    ax.set_title(title, fontsize=12, fontweight='bold')
    ax.set_ylim(ylim)
    ax.grid(True, alpha=0.25)

# Shared x-label
for ax in axes[1]:
    ax.set_xlabel('Time (seconds)', fontsize=11)

# Single shared legend at bottom
handles, labels = axes[0, 0].get_legend_handles_labels()
fig.legend(handles, labels, loc='lower center', ncol=2, fontsize=11,
           frameon=True, bbox_to_anchor=(0.5, 0.01))

plt.tight_layout(rect=[0, 0.05, 1, 0.96])
out = '/home/ronit/MTP/PQC_DDOS/partial/mode_comparison_dashboard.png'
plt.savefig(out, dpi=150)
print(f"Plot saved to {out}")
