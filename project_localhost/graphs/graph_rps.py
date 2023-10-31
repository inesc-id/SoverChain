import matplotlib.pyplot as plt

# Data for the plot
rps = [1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5]
median_response_time = [77, 78, 120.0, 220.0, 270.0, 380.0, 670.0, 360.0, 430.0]
average_response_time = [114.53, 128.59, 177.36, 263.92, 300.13, 389.02, 856.34, 512.94, 587.18]
min_response_time = [55.72, 52.65, 51.17, 55.11, 52.63, 57.91, 116.60, 52.61, 58.33]
max_response_time = [267.89, 415.10, 421.10, 663.55, 604.35, 773.86, 1514.92, 1060.92, 1227.84]

# Create the plot
plt.figure(figsize=(10, 6))
plt.plot(rps, median_response_time, marker='o', label='Median')
plt.plot(rps, average_response_time, marker='o', label='Average')
plt.plot(rps, min_response_time, marker='o', label='Min')
plt.plot(rps, max_response_time, marker='o', label='Max')

# Add labels and title
plt.xlabel('RPS (Requests/s)')
plt.ylabel('Response Time (ms)')
plt.title('Response Time Statistics')
plt.grid(True)

# Add legend
plt.legend()

# Save the plot as an image
plt.savefig('plot_rps_final.pdf')

# Show the plot (optional, remove this line if you don't want to see the plot)
plt.show()
