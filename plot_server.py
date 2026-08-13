import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df_768 = pd.read_csv('/home/ronit/MTP/PQC_DDOS/plots/mlkem768_metrics.csv').head(50)
df_1024 = pd.read_csv('/home/ronit/MTP/PQC_DDOS/plots/mlkem1024_metrics.csv').head(50)
df_classical = pd.read_csv('/home/ronit/MTP/PQC_DDOS/plots/X25519_metrics.csv').head(50)
# df_p384_mlkem768 = pd.read_csv('/home/ronit/MTP/PQC_DDOS/final_plotss/p384_mlkem768_metrics.csv').head(50)
# df_p521_mlkem1024 = pd.read_csv('/home/ronit/MTP/PQC_DDOS/final_plotss/p521_mlkem1024_metrics.csv').head(50)


# Plotting
plt.figure(figsize=(10, 6))

# We use the index of the dataframe for the x-axis, assuming one data point per second
plt.plot(df_768.index, df_768['avg_handshake_cycles'], label='MLKEM-768', marker='o', markersize=3, linestyle='-')
plt.plot(df_1024.index, df_1024['avg_handshake_cycles'], label='MLKEM-1024', marker='s', markersize=3, linestyle='-')
plt.plot(df_classical.index, df_classical['avg_handshake_cycles'], label='Classical (X25519)', marker='^', markersize=3, linestyle='-')
# plt.plot(df_p384_mlkem768.index, df_p384_mlkem768['avg_handshake_cycles'], label='P384 + MLKEM-768', marker='v', markersize=3, linestyle='-')
# plt.plot(df_p521_mlkem1024.index, df_p521_mlkem1024['avg_handshake_cycles'], label='P521 + MLKEM-1024', marker='D', markersize=3, linestyle='-')

# Add title and labels
plt.title('Server average Handshake Cycles Comparison over Time')
plt.xlabel('Time')
plt.ylabel('Average Handshake Cycles')
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
plt.savefig('/home/ronit/MTP/PQC_DDOS/comparison_server_plot.png')
print("Plot saved to /home/ronit/MTP/PQC_DDOS/comparison_server_plot.png")
