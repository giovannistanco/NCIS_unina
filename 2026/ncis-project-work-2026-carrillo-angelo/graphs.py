import pandas as pd
import matplotlib.pyplot as plt

# Carica i dati
df = pd.read_json('mir_metrics.jsonl', lines=True)
hosts = df[df.type == 'host_window']

# Stile uniforme dei grafici
def save_graph(filename, title, ylabel):
    plt.figure(figsize=(10, 6))
    for ip in hosts['ip'].unique():
        subset = hosts[hosts['ip'] == ip]
        plt.plot(subset['window'], subset[ylabel.lower().replace(' ', '_')], label=f'Host {ip}')
    plt.title(title)
    plt.xlabel('Finestra Temporale')
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(True)
    plt.savefig(filename)
    plt.close()

# Generazione dei grafici e salvataggio dei grafici
save_graph('mir_trend.png', 'Andamento MIR per Host', 'MIR Local')
save_graph('throughput.png', 'Throughput per Host (RPS)', 'Throughput RPS')
save_graph('latency.png', 'Latenza Media per Host (ms)', 'Avg Latency ms')

# Stampa informativa
print("Grafici salvati correttamente: mir_trend.png, throughput.png, latency.png")