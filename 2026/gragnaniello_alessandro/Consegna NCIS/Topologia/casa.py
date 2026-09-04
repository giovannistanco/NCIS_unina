from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.net import Mininet, CLI
from mininet.node import RemoteController

# Numero di host della LAN emulata: unico punto in cui si cambia il
# dimensionamento, cosi' i due modi di lancio (python3 / --custom)
# costruiscono sempre la stessa rete.
N_HOST = 13


class casaTopo(Topo):
    """Emula una LAN domestica: uno switch e una decina di host
    tra PC, smartphone, TV, stampante e dispositivi IoT."""

    def build(self, n=N_HOST):
        """Chiamata automaticamente dal costruttore ereditato da Topo.
        Istanzia uno switch e n host collegati a stella."""

        # Unico switch della LAN
        switch = self.addSwitch('s1')

        # n host, con MAC e IP espliciti e coerenti fra loro:
        # l'host i-esimo ha MAC ...:{i in esadecimale} e IP 10.0.0.{i}.
        for h in range(n):
            host = self.addHost(f'h{h+1}',
                                mac=f'00:00:00:00:00:{h+1:02x}',
                                ip=f'10.0.0.{h+1}')

            # Un link host <-> switch: topologia a stella
            self.addLink(host, switch)

        # I link sono senza shaping artificiale: quindi sono ideali


def create_net():
    """Costruisce e avvia la rete a partire dalla topologia definita sopra.
    build() descrive il grafo; qui si sceglie come realizzarlo (tipo di
    controller, avvio, CLI)."""

    # Istanzia la topologia: il grafo esiste in memoria, nessun processo
    # e' ancora stato creato
    topo = casaTopo(n=N_HOST)

    # Costruisce la rete a partire dal grafo, dichiarando che il
    # controller e' esterno (Ryu su 127.0.0.1:6653)
    net = Mininet(topo, controller=RemoteController)


    # Avvia switch e controller e apre il canale OpenFlow
    net.start()

    # Prompt mininet> per lavorare a mano. Bloccante: la riga successiva
    # viene eseguita solo dopo 'exit'
    CLI(net)

    # Smonta la rete: host, link e switch
    net.stop()


if __name__ == "__main__":
    setLogLevel('info')
    create_net()


# Permette il lancio alternativo: sudo mn --custom casa.py --topo casa
topos = {'casa': (lambda: casaTopo(n=N_HOST))}