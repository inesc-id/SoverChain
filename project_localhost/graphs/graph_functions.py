import matplotlib.pyplot as plt

# Function names
functions = [
    "1- Creating DID",
    "2- Establish connection",
    "3- Issue credential",
    "4- Present credential",
    "5- Storj upload",
    "6- Storj delete",
    "7- Storj share",
    "8- Create audit log",
    "9- Read audit log",
]

# Latency portions for each function (except the first one)
latency_portions = [
    [0.132],  # Creating DID has no portions
    [0.026, 0.018, 0.030],
    [0.327, 0.0451, 0.269, 0.049],
    [0.095, 0.179, 0.288],
    [2],  # Storj upload has no portions
    [0.643],  # Storj delete has no portions
    [0.073],  # Storj share has no portions
    [0.02, 0.117],
    [0.0329, 0.0071],
]

# Names for each portion within a bar
portion_names = [
    ["Creating DID"],
    ["Create Invitation", "Request Invitation", "Accept connection"],
    ["Request validation", "Accept offer", "Issuing credential", "Store credential"],
    ["Presentation requested", "Create presentation", "Verify presentation"],
    ["Storj upload"],
    ["Storj delete"],
    ["Storj share"],
    ["Encrypt log", "Submit to ledger"],
    ["Read from ledger", "Decrypt log"],
]

# Colors for each portion within a bar
portion_colors = [
    ["#1f77b4"],  # Creating DID (Blue)
    ["#8c564b", "#EADDCA", "#2ca02c"],  # Establish connection (Brown, Red, Green)
    ["#bcbd22", "#9467bd", "#e377c2", "#17becf"],  # Issue credential (Yellow, Purple, Pink, Cyan)
    ["#7f7f7f", "#ffbb78", "#aec7e8"],  # Present credential (Gray, Light Orange, Light Blue)
    ["#ff7f0e"],  # Storj upload (Light Red)
    ["#ff7f0e"],  # Storj delete (Light Green)
    ["#ff7f0e"],  # Storj share (Orange)
    ["#d62728", "#f7b6d2"],  # Create audit log (Lavender, Light Brown)
    ["#f7b6d2", "#d62728"],  # Read audit log (Pink, Light Yellow)
]

# Create the bar chart
fig, ax = plt.subplots()
for i, (func, portions) in enumerate(zip(functions, latency_portions)):
    if not portions:  # Function has no portions
        ax.bar(i, 0, color=portion_colors[i][0])  # Empty bar for label
    else:
        bottom = 0
        for j, (portion, name) in enumerate(zip(portions, portion_names[i])):
            ax.bar(
                i,
                portion,
                bottom=bottom,
                color=portion_colors[i][j % len(portion_colors[i])],
                label=f"{i+1}-{name}",
            )
            bottom += portion

# Set the labels and title
ax.set_ylabel("Latency (s)")
ax.set_xticks(range(len(functions)))
ax.set_xticklabels(functions, rotation=45, ha="right")

handles, labels = ax.get_legend_handles_labels()
ax.legend(handles, labels, bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0.)



# Show the plot
plt.tight_layout()
plt.savefig("function_latency_breakdown1.pdf")
plt.show()
