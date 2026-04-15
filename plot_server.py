import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df_768 = pd.read_csv('/home/ronit/MTP/PQC_DDOS/metrics_768.csv')
df_1024 = pd.read_csv('/home/ronit/MTP/PQC_DDOS/metrics_1024.csv')
df_classical = pd.read_csv('/home/ronit/MTP/PQC_DDOS/metrics_classical.csv')

# Plotting
plt.figure(figsize=(10, 6))

# We use the index of the dataframe for the x-axis, assuming one data point per second
plt.plot(df_768.index, df_768['avg_handshake_cycles'], label='MLKEM-768', marker='o', markersize=3, linestyle='-')
plt.plot(df_1024.index, df_1024['avg_handshake_cycles'], label='MLKEM-1024', marker='s', markersize=3, linestyle='-')
plt.plot(df_classical.index, df_classical['avg_handshake_cycles'], label='Classical (X25519)', marker='^', markersize=3, linestyle='-')

# Add title and labels
plt.title('Server average Handshake Cycles Comparison over Time')
plt.xlabel('Time')
plt.ylabel('Average Handshake Cycles')
plt.legend()
plt.grid(True)

# Add vertical lines to delineate the 3 phases of the mininet experiment (Baseline, Attack, Recovery)
# Given a 45 second experiment, Phase 1 is 1-15, Phase 2 is 16-30, Phase 3 is 31-45
# So the transitions are around 15 and 30 for the x-axis index.
plt.axvline(x=15, color='r', linestyle='--', alpha=0.5, label='Attack Start')
plt.axvline(x=30, color='g', linestyle='--', alpha=0.5, label='Attack End (Recovery)')

# Fix duplicate legend entries from vertical lines
handles, labels = plt.gca().get_legend_handles_labels()
by_label = dict(zip(labels, handles))
plt.legend(by_label.values(), by_label.keys())

plt.tight_layout()

# Save the plot
plt.savefig('/home/ronit/MTP/PQC_DDOS/comparison_server_plot.png')
print("Plot saved to /home/ronit/MTP/PQC_DDOS/comparison_server_plot.png")
