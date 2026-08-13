import pandas as pd
import matplotlib.pyplot as plt

# Base directory for all metrics
BASE_DIR = '/home/ronit/MTP/PQC_DDOS/plots'

# Define all 6 collected metrics with their filenames and labels
datasets = [
    ('mlkem768_client_metrics.csv',              'MLKEM-768',            'o'),
    ('mlkem1024_client_metrics.csv',             'MLKEM-1024',           's'),
    ('X25519_client_metrics.csv',        'Classical (X25519)',    '^'),
    ('p521_mlkem1024_client_metrics.csv',    'P521 + MLKEM-1024',     'D'),
    ('p384_mlkem768_client_metrics.csv',  'P384 + MLKEM-768', 'v'),
]

# Load all dataframes
dfs = {}
for filename, label, _ in datasets:
    dfs[label] = pd.read_csv(f'{BASE_DIR}/{filename}')

# Plotting
plt.figure(figsize=(12, 7))

for filename, label, marker in datasets:
    df = dfs[label]
    plt.plot(df.index, df['handshake_cycles'], label=label, marker=marker, markersize=3, linestyle='-')

# Add title and labels
plt.title('Client Handshake Cycles Comparison over Time')
plt.xlabel('Data Point (Handshake Number / Time)')
plt.ylabel('Handshake Cycles')
plt.legend()
plt.grid(True)

# Add vertical lines to delineate the 3 phases of the mininet experiment (Baseline, Attack, Recovery)
# Given a 45 second experiment, Phase 1 is 1-15, Phase 2 is 16-30, Phase 3 is 31-45
# So the transitions are around 15 and 30 for the x-axis index.
plt.axvline(x=15, color='r', linestyle='--', alpha=0.5)
plt.axvline(x=30, color='g', linestyle='--', alpha=0.5)

# Add annotations with arrows pointing to the vertical lines
plt.annotate('Attack\nStart', xy=(15, 0.85), xycoords=('data', 'axes fraction'),
             xytext=(8, 0.85), textcoords=('data', 'axes fraction'),
             arrowprops=dict(facecolor='red', width=2, headwidth=8),
             ha='center', va='center', color='red', fontweight='bold')

plt.annotate('Attack\nEnd', xy=(30, 0.85), xycoords=('data', 'axes fraction'),
             xytext=(37, 0.85), textcoords=('data', 'axes fraction'),
             arrowprops=dict(facecolor='green', width=2, headwidth=8),
             ha='center', va='center', color='green', fontweight='bold')

plt.tight_layout()

# Save the plot
plt.savefig('/home/ronit/MTP/PQC_DDOS/comparison_plot.png', dpi=150)
print("Plot saved to /home/ronit/MTP/PQC_DDOS/comparison_plot.png")
