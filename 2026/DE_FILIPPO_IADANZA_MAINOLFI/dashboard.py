import requests 
import time
from flask import Flask, jsonify, render_template_string 

app = Flask(__name__) # inizializza l'app Flask per il dashboard

# DEFINIZIONE URL
RYU_URL = 'http://127.0.0.1:8080/stats/port/1'

# Variabili per calcolare la lunghezza di banda 
stats = {
    'video_bw': 0.0, #ultima lunghezza di banda calcolata per il traffico video
    'besteffort_bw': 0.0, 
    'last_time': time.time(), 
    'last_bytes_video': 0, #contatore di byte trasmessi dall'ultima richiesta per il traffico video
    'last_bytes_be': 0 #contatore di byte trasmessi dall'ultima richiesta per il traffico best-effort
}

HTML_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SDN Slicing Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }
        h1 { text-align: center; color: #2c3e50; font-size: 2.5em; margin-bottom: 30px; }
        .container { display: flex; justify-content: space-around; flex-wrap: wrap; }
        .card { background: white; border-radius: 12px; box-shadow: 0 6px 12px rgba(0,0,0,0.1); padding: 25px; width: 45%; margin-bottom: 20px; text-align: center; }
        canvas { max-width: 100%; margin-top: 15px; }
        .metrics { font-size: 1.1em; color: #7f8c8d; margin-top: 15px; background: #ecf0f1; padding: 10px; border-radius: 8px; }
        .highlight { color: #e74c3c; font-weight: bold; font-size: 1.2em; }
        .highlight-video { color: #3498db; font-weight: bold; font-size: 1.2em; }
    </style>
</head>
<body>
    <h1>Real-Time Slicing Dashboard</h1>
    <div class="container">
        <div class="card">
            <h2>Upper Slice (Video)</h2>
            <div class="metrics">Banda Max: <strong>10 Mbps</strong> | Delay: <strong>< 1 ms</strong></div>
            <canvas id="videoChart"></canvas>
            <div style="margin-top: 15px;">Traffico: <span id="videoVal" class="highlight-video">0.00</span> Mbps</div>
        </div>
        <div class="card">
            <h2>Lower Slice (Best-Effort)</h2>
            <div class="metrics">Banda Max: <strong>1 Mbps</strong> | Delay: <strong>Variabile</strong></div>
            <canvas id="beChart"></canvas>
            <div style="margin-top: 15px;">Traffico: <span id="beVal" class="highlight">0.00</span> Mbps</div>
        </div>
    </div>
    <script>
        const chartConfig = (label, color, maxVal) => ({
            type: 'line',
            data: { labels: Array(20).fill(''), datasets: [{ label: label + ' (Mbps)', data: Array(20).fill(0), borderColor: color, backgroundColor: color + '33', borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0 }] },
            options: { responsive: true, scales: { y: { beginAtZero: true, suggestedMax: maxVal }, x: { grid: { display: false } } }, animation: { duration: 0 }, plugins: { legend: { display: false } } }
        });

        const videoChart = new Chart(document.getElementById('videoChart').getContext('2d'), chartConfig('Video Traffic', '#3498db', 12));
        const beChart = new Chart(document.getElementById('beChart').getContext('2d'), chartConfig('Best-Effort', '#e74c3c', 2));

        function updateCharts() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    videoChart.data.datasets[0].data.push(data.video_bw); videoChart.data.datasets[0].data.shift(); videoChart.update();
                    document.getElementById('videoVal').innerText = data.video_bw.toFixed(2);
                    beChart.data.datasets[0].data.push(data.besteffort_bw); beChart.data.datasets[0].data.shift(); beChart.update();
                    document.getElementById('beVal').innerText = data.besteffort_bw.toFixed(2);
                }).catch(err => console.error("Errore API:", err));
        }
        setInterval(updateCharts, 1000); 
    </script>
</body>
</html>
'''

@app.route('/') # definisce la route principale per il dashboard, che restituisce la pagina HTML
def index():    # funzione che gestisce la route principale
    return render_template_string(HTML_PAGE)

@app.route('/api/data') # definisce la route per ottenere i dati in tempo reale dal controller Ryu
def get_data(): 
    global stats   # globale perchè vogliamo poter aggiornare i valori
    try:
        response = requests.get(RYU_URL, timeout=1) #richiesta GET al controller Ryu per ottenere le statistiche delle porte dello switch s1
        if response.status_code == 200: # 200: risposta a buon fine, prendo i dati json dal link
            data = response.json()
            port_stats = data.get('1', [])  # ottengo le statistiche della porta 1 (Upper Slice) dallo switch s1, se manca prendo una lista vuota
            current_time = time.time()
            time_diff = current_time - stats['last_time'] #secondi trascorsi dall'ultima richiesta, per calcolare la lunghezza di banda
            
            if time_diff > 0: #se è passato del tempo dall'ultima richiesta, calcolo la lunghezza di banda per ciascuna slice
                for port in port_stats:
                    if port['port_no'] == 2: # se la porta è la 2 (Upper Slice), calcolo la lunghezza di banda per il traffico video
                        curr_bytes = port['tx_bytes']
                        if stats['last_bytes_video'] > 0:
                            stats['video_bw'] = round(((curr_bytes - stats['last_bytes_video']) * 8) / (1000000 * time_diff), 2) # 8: numero bit inviati, 1000000: converto in Mbps, 2: arrotondo a 2 decimali
                        stats['last_bytes_video'] = curr_bytes # salvo i dati correnti per il prossimo calcolo della lunghezza di banda
                    elif port['port_no'] == 4: # Lower Slice, stessa cosa di prima ma per il traffico best-effort
                        curr_bytes = port['tx_bytes']
                        if stats['last_bytes_be'] > 0:
                            stats['besteffort_bw'] = round(((curr_bytes - stats['last_bytes_be']) * 8) / (1000000 * time_diff), 2)
                        stats['last_bytes_be'] = curr_bytes
            stats['last_time'] = current_time
    except Exception: # se la richiesta fallisce, azzero i contatori, così da non mostrare dati vecchi o errati
        stats['video_bw'] = 0.0
        stats['besteffort_bw'] = 0.0
        
    return jsonify({'video_bw': max(0, stats['video_bw']), 'besteffort_bw': max(0, stats['besteffort_bw'])}) # restituisco i dati in formato JSON, con valori minimi a 0 per evitare valori negativi in caso di errori

if __name__ == '__main__': # se il file viene eseguito direttamente, avvia il server Flask per il dashboard
    print("Dashboard avviata, apri il browser su: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False) # host tutti a 0 per permettere l'accesso da qualsiasi interfaccia, porta 5000 è standard di flask, debug disattivato per evitare messaggi di log eccessivi
