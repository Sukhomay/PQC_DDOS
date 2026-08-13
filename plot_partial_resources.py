import pandas as pd
import matplotlib.pyplot as plt

# Load the data and strip leading zero rows
def load_and_trim(path):
    df = pd.read_csv(path)
    # Drop leading rows where total_connections == 0
    first_nonzero = df[df['total_connections'] > 0].index
    if len(first_nonzero) > 0:
        start = max(0, first_nonzero[0] - 1)  # keep 1 zero row for context
        df = df.iloc[start:].reset_index(drop=True)
    return df.head(50)

BASE = '/home/ronit/MTP/PQC_DDOS/partial'

df_768 = load_and_trim(f'{BASE}/mlkem768_metrics.csv')
df_1024 = load_and_trim(f'{BASE}/mlkem1024_metrics.csv')
df_classical = load_and_trim(f'{BASE}/X25519_metrics.csv')

# Plotting
fig, ax = plt.subplots(figsize=(12, 7))

ax.plot(df_768.index, df_768['total_connections'],
        label='MLKEM-768', marker='o', markersize=4, linestyle='-', color='#1f77b4')
ax.plot(df_1024.index, df_1024['total_connections'],
        label='MLKEM-1024', marker='s', markersize=4, linestyle='-', color='#ff7f0e')
ax.plot(df_classical.index, df_classical['total_connections'],
        label='Classical (X25519)', marker='^', markersize=4, linestyle='-', color='#2ca02c')

# OS limit line
ax.axhline(y=4046, color='gray', linestyle='--', alpha=0.6)
ax.text(48, 4100, 'OS limit (~4046)', ha='right', va='bottom',
        color='gray', fontsize=10, fontstyle='italic')

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
ax.set_ylabel('Total Connections (File Descriptors Consumed)', fontsize=12)
ax.set_title('Server Total Connections — Partial Handshake Attack (Mode 2)',
             fontsize=14, fontweight='bold')
ax.legend(fontsize=10, loc='center left')
ax.grid(True, alpha=0.3)
ax.set_ylim(-100, 4800)

plt.tight_layout()
plt.savefig(f'{BASE}/partial_server_resources.png', dpi=150)
print(f"Plot saved to {BASE}/partial_server_resources.png")
