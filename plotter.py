import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df = pd.read_csv('/home/ronit/MTP/PQC_DDOS/client_metrics.csv')

# Convert timestamp to relative time (seconds from start)
df['time'] = df['timestamp'] - df['timestamp'].iloc[0]

# Plotting
plt.figure(figsize=(12, 6))

plt.plot(df['time'], df['handshake_cycles'], marker='.', markersize=2, linestyle='-', linewidth=0.5, label='Handshake Cycles')

# Add title and labels
plt.title('Client Handshake Cycles vs Time')
plt.xlabel('Time (seconds from start)')
plt.ylabel('Handshake Cycles')
plt.legend()
plt.grid(True)

plt.tight_layout()

# Save the plot
plt.savefig('/home/ronit/MTP/PQC_DDOS/comparison_plot.png', dpi=150)
print("Plot saved to /home/ronit/MTP/PQC_DDOS/comparison_plot.png")
