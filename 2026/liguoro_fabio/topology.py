#!/usr/bin/python3
import sys
import time

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# PARAMETRI DI RETE

# Capacita' dei link fra switch
CORE_BW_MBPS = 10

# Capacita' dei link host-switch
EDGE_BW_MBPS = 20

# Ritardo di propagazione applicato a ogni link di core.
CORE_DELAY = '2ms'


class DiamondTopo(Topo):
    def build(self):
        # SWITCH
        # Il dpid (DataPath IDentifier) e' l'identificativo univoco a 64 bit
        # con cui lo switch si presenta al controller durante l'handshake
        # OpenFlow. Lo forziamo esplicitamente perche' ci serve che sia
        # deterministico e non dipenda dall'ordine di creazione.
        s1 = self.addSwitch('s1', dpid='0000000000000001')
        s2 = self.addSwitch('s2', dpid='0000000000000002')
        s3 = self.addSwitch('s3', dpid='0000000000000003')
        s4 = self.addSwitch('s4', dpid='0000000000000004')

        # HOST
        # Fissiamo IP e MAC di ogni host
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # LINK
        # Link di accesso (host - switch di bordo)
        self.addLink(h1, s1, port1=0, port2=1, bw=EDGE_BW_MBPS)
        self.addLink(h2, s1, port1=0, port2=2, bw=EDGE_BW_MBPS)
        self.addLink(h3, s4, port1=0, port2=1, bw=EDGE_BW_MBPS)
        self.addLink(h4, s4, port1=0, port2=2, bw=EDGE_BW_MBPS)

        # Percorso PRIMARIO: s1 -> s2 -> s4
        self.addLink(s1, s2, port1=3, port2=1,
                     bw=CORE_BW_MBPS, delay=CORE_DELAY)
        self.addLink(s2, s4, port1=2, port2=3,
                     bw=CORE_BW_MBPS, delay=CORE_DELAY)

        # Percorso SECONDARIO: s1 -> s3 -> s4
        self.addLink(s1, s3, port1=4, port2=1,
                     bw=CORE_BW_MBPS, delay=CORE_DELAY)
        self.addLink(s3, s4, port1=2, port2=4,
                     bw=CORE_BW_MBPS, delay=CORE_DELAY)


def configure_hosts(net):
    hosts = {h.name: h for h in net.hosts}

    # Tabella statica nome -> (indirizzo IP, indirizzo MAC)
    addresses = {
        'h1': ('10.0.0.1', '00:00:00:00:00:01'),
        'h2': ('10.0.0.2', '00:00:00:00:00:02'),
        'h3': ('10.0.0.3', '00:00:00:00:00:03'),
        'h4': ('10.0.0.4', '00:00:00:00:00:04'),
    }

    for name, host in hosts.items():
        # Disabilita IPv6 su tutte le interfacce dell'host
        host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')

        # Inserisce una entry ARP permanente per ogni ALTRO host della rete
        for peer_name, (peer_ip, peer_mac) in addresses.items():
            if peer_name != name:
                host.cmd('arp -s %s %s' % (peer_ip, peer_mac))

    info('*** Entry ARP statiche configurate, IPv6 disabilitato\n')


def run_demo(net):
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    info('*** Avvio dei server iperf3 su h3 e h4\n')
    # -s = modalita' server, -D = esegui come demone
    h3.cmd('iperf3 -s --logfile /tmp/iperf_server_h3.log -D')
    h4.cmd('iperf3 -s --logfile /tmp/iperf_server_h4.log -D')

    info('*** t=0s  : flusso A (h1 -> h3), UDP 2 Mbps, 110 s\n')
    # -u = UDP, -b = bitrate target, -t = durata, -l = dimensione del payload.
    # 1400 byte sta sotto la MTU di 1500 (quindi niente frammentazione IP) e
    # riduce il numero di pacchetti al secondo rispetto a un payload piccolo
    # La & finale manda il comando in background
    h1.cmd('iperf3 -c 10.0.0.3 -u -b 2M -t 110 -l 1400 '
           '--logfile /tmp/iperf_client_A.log &')

    info('*** t=20s : flusso B (h2 -> h4), UDP 8 Mbps, 30 s (programmato)\n')
    # 8 Mbps: sommati ai 2 Mbps del flusso A saturano il percorso primario
    # (10 Mbps richiesti su 10 disponibili), ma una volta spostato su un percorso
    # dedicato il flusso B dispone di 2 Mbps di margine. Serve ad assorbire
    # le raffiche di iperf3: dopo un periodo di congestione lo strumento
    # tenta di recuperare l'arretrato trasmettendo piu' velocemente del
    # bitrate nominale, e senza margine quelle raffiche verrebbero scartate
    # dalla coda anche in assenza di congestione reale.
    h2.cmd('sh -c "sleep 20; iperf3 -c 10.0.0.4 -u -b 8M -t 30 -l 1400 '
           '--logfile /tmp/iperf_client_B.log" &')

    info('\n*** Esperimento avviato. Osservare i log del controller.\n')
    info('*** Misure raccolte in /tmp/te_monitor.csv\n')
    info('*** Cronologia attesa:\n')
    info('***    ~t=22s  REROUTE verso il percorso secondario\n')
    info('***    ~t=56s  REROUTE di rientro sul percorso primario\n')
    info('*** ATTENDERE 115 SECONDI, poi uscire dalla CLI con "exit".\n')
    info('*** Uscire prima significa perdere il secondo rerouting.\n\n')


def run(demo=False):
    topo = DiamondTopo()

    net = Mininet(
        topo=topo,
        # OVSKernelSwitch: Open vSwitch con datapath nel kernel Linux
        switch=OVSKernelSwitch,
        # RemoteController: gli switch si connettono via TCP al nostro controller Ryu sulla porta 6653
        controller=lambda name: RemoteController(name, ip='127.0.0.1',
                                                 port=6653),
        # TCLink: Applica i limiti di banda e i ritardi tramite il modulo tc del kernel Linux
        link=TCLink,
        autoSetMacs=False,   # i MAC li abbiamo gia' fissati in build()
        autoStaticArp=False  # l'ARP lo configuriamo in configure_hosts()
    )

    net.start()

    # Forziamo la versione del protocollo OpenFlow a 1.3 su ogni switch
    for sw in net.switches:
        sw.cmd('ovs-vsctl set bridge %s protocols=OpenFlow13' % sw.name)

    configure_hosts(net)

    info('\n*** Topologia attiva.\n')
    info('*** Percorso primario:   s1 -(porta 3)- s2 -- s4\n')
    info('*** Percorso secondario: s1 -(porta 4)- s3 -- s4\n')

    if demo:
        # Piccola attesa per garantire che gli switch hanno completato l'handshake
        # e ricevuto le flow entry prima che parta il traffico.
        time.sleep(3)
        run_demo(net)
    else:
        info('*** Avviare la demo manualmente dalla CLI, oppure rilanciare\n')
        info('*** questo script con l\'opzione --demo\n\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run(demo='--demo' in sys.argv)
