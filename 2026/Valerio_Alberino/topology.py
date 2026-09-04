from mininet.topo import Topo
from mininet.link import TCLink
import json

class MyTopo(Topo):
    def build(self):
        # Inizializzazione dei 5 Switch OVS
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3') # Core Switch
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        # Definizione dei 4 Host con IP e MAC statici
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01') # Attaccante
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # Lecito
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') # Server Vittima
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04') # Ausiliario

        # Link Access: Host -> Switch
        self.addLink(h1, s1, cls=TCLink, bw=100) # porta 1 su s1
        self.addLink(h2, s2, cls=TCLink, bw=100) # porta 1 su s2
        self.addLink(h4, s4, cls=TCLink, bw=100) # porta 1 su s4
        self.addLink(h3, s5, cls=TCLink, bw=10)  # porta 1 su s5 (BOTTLENECK a 10 Mbps)

        # Link Core: Switch periferici -> Switch centrale (S3)
        self.addLink(s1, s3, cls=TCLink, bw=100) # s1 porta 2 <-> s3 porta 1
        self.addLink(s2, s3, cls=TCLink, bw=100) # s2 porta 2 <-> s3 porta 2
        self.addLink(s4, s3, cls=TCLink, bw=100) # s4 porta 2 <-> s3 porta 3
        self.addLink(s5, s3, cls=TCLink, bw=100) # s5 porta 2 <-> s3 porta 4

        # Mappa (DPID, porta) -> Banda in Mbps per il calcolo dinamico delle soglie
        port_bw = {
            "1,1": 100,
            "1,2": 100,
            "2,1": 100,
            "2,2": 100,
            "3,1": 100,
            "3,2": 100,
            "3,3": 100,
            "3,4": 100,
            "4,1": 100,
            "4,2": 100,
            "5,1": 10,  # Collo di bottiglia per H3 (soglia a 208 pkts/0.5s)
            "5,2": 100
        }

        # Salvataggio su file JSON all'avvio
        with open('/tmp/port_bw.json', 'w') as f:
            json.dump(port_bw, f)

topos = { 'mytopo': ( lambda: MyTopo() ) }

