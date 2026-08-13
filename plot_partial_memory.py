import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Estimated per-connection memory overhead on the server:
#   SSL object + session state:  ~100 KB
#   Socket kernel buffers:       ~128 KB  (send + recv)
#   Thread stack (reduced):      ~  64 KB (pthread with small stack)
# Total estimate per held connection: ~292 KB ≈ 0.285 MB
MEM_PER_CONN_MB = 0.285

def load_and_trim(path):
    df = pd.read_csv(path)
    first_nonzero = df[df['total_connections'] > 0].index
    if len(first_nonzero) > 0:
        start = max(0, first_nonzero[0] - 1)
        df = df.iloc[start:].reset_index(drop=True)
    return df.head(50)

BASE = '/home/ronit/MTP/PQC_DDOS/partial'

df_768 = load_and_trim(f'{BASE}/mlkem768_metrics.csv')
df_1024 = load_and_trim(f'{BASE}/mlkem1024_metrics.csv')
df_classical = load_and_trim(f'{BASE}/X25519_metrics.csv')

# Compute estimated memory usage (MB)
df_768['mem_mb'] = df_768['total_connections'] * MEM_PER_CONN_MB
df_1024['mem_mb'] = df_1024['total_connections'] * MEM_PER_CONN_MB
df_classical['mem_mb'] = df_classical['total_connections'] * MEM_PER_CONN_MB

# Plotting
fig, ax = plt.subplots(figsize=(12, 7))

ax.plot(df_768.index, df_768['mem_mb'],
        label='MLKEM-768', marker='o', markersize=4, linestyle='-', color='#1f77b4')
ax.plot(df_1024.index, df_1024['mem_mb'],
        label='MLKEM-1024', marker='s', markersize=4, linestyle='-', color='#ff7f0e')
ax.plot(df_classical.index, df_classical['mem_mb'],
        label='Classical (X25519)', marker='^', markersize=4, linestyle='-', color='#2ca02c')

# Ceiling line
ceiling_mb = 4046 * MEM_PER_CONN_MB
ax.axhline(y=ceiling_mb, color='gray', linestyle='--', alpha=0.6)
ax.text(48, ceiling_mb + 20, f'Plateau (~{ceiling_mb:.0f} MB)',
        ha='right', va='bottom', color='gray', fontsize=10, fontstyle='italic')

# Phase markers
ax.axvline(x=15, color='r', linestyle='--', alpha=0.5)
ax.axvline(x=30, color='g', linestyle='--', alpha=0.5)

ax.annotate('Attack\nStart', xy=(15, 0.55), xycoords=('data', 'axes fraction'),
            xytext=(8, 0.55), textcoords=('data', 'axes fraction'),
            arrowprops=dict(facecolor='red', width=2, headwidth=8),
            ha='center', va='center', color='red', fontweight='bold', fontsize=11)

ax.annotate('Attack\nEnd', xy=(30, 0.55), xycoords=('data', 'axes fraction'),
            xytext=(37, 0.55), textcoords=('data', 'axes fraction'),
            arrowprops=dict(facecolor='green', width=2, headwidth=8),
            ha='center', va='center', color='green', fontweight='bold', fontsize=11)

ax.set_xlabel('Time (seconds)', fontsize=12)
ax.set_ylabel('Estimated Server Memory Consumed (MB)', fontsize=12)
ax.set_title('Server Memory Consumption — Partial Handshake Attack (Mode 2)',
             fontsize=14, fontweight='bold')
ax.legend(fontsize=10, loc='center left')
ax.grid(True, alpha=0.3)
ax.set_ylim(-30, ceiling_mb + 200)

plt.tight_layout()
out = f'{BASE}/partial_server_memory.png'
plt.savefig(out, dpi=150)
print(f"Plot saved to {out}")
