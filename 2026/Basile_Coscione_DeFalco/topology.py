from mininet.net import Mininet                              # gestisce l'intera rete emulata
from mininet.node import RemoteController, OVSKernelSwitch   # controller esterno (Ryu) e switch Open vSwitch
from mininet.link import TCLink                              # link con banda, ritardo e coda configurabili
from mininet.cli import CLI                                  # il prompt mininet
from mininet.log import setLogLevel, info                    # messaggi a terminale

# PARAMETRI DEI LINK
# n.b: i link host-switch di accesso NON sono limitati in banda
UPPER_BW = 10         # Mbit/s, link verso s4 (slice UPPER, percorso principale)
UPPER_DELAY = '2ms'
LOWER_BW = 2          # Mbit/s, link verso s5 (slice LOWER, percorso secondario)
LOWER_DELAY = '5ms'   # ritardo più alto: dal ping si capisce quale percorso si usa
QUEUE_SIZE = 100      # pacchetti in coda (FIFO) sui link verso s4 e s5: oltre, si scarta


def build_network():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=False, build=False)
        # build=False: la rete si costruisce dopo aver dichiarato tutto

    # il controller è Ryu, sulla stessa VM, porta standard di OpenFlow
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    # HOST
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')   # sorgente UDP, s1
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24')   # sorgente TCP, s1
    h3 = net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3/24')   # sorgente UDP, s2
    h4 = net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4/24')   # sorgente TCP, s2
    h5 = net.addHost('h5', mac='00:00:00:00:00:05', ip='10.0.0.5/24')   # server, s3

    # SWITCH (dpid = numero con cui lo switch si presenta al controller, uguale al numero nel nome)
    s1 = net.addSwitch('s1', dpid='1', protocols='OpenFlow13')    # accesso
    s2 = net.addSwitch('s2', dpid='2', protocols='OpenFlow13')    # accesso
    s3 = net.addSwitch('s3', dpid='3', protocols='OpenFlow13')    # accesso
    s4 = net.addSwitch('s4', dpid='4', protocols='OpenFlow13')    # transito: slice UPPER
    s5 = net.addSwitch('s5', dpid='5', protocols='OpenFlow13')    # transito: slice LOWER

    # LINK HOST - SWITCH DI ACCESSO (sugli host la porta è 0, cioe' l'interfaccia eth0)
    net.addLink(h1, s1, port1=0, port2=3)
    net.addLink(h2, s1, port1=0, port2=4)
    net.addLink(h3, s2, port1=0, port2=3)
    net.addLink(h4, s2, port1=0, port2=4)
    net.addLink(h5, s3, port1=0, port2=3)

    # LINK ACCESSO - S4 (slice UPPER): porta 1 dello switch di accesso, porta j-esima di s4 verso sj
    net.addLink(s1, s4, port1=1, port2=1, bw=UPPER_BW, delay=UPPER_DELAY, max_queue_size=QUEUE_SIZE)
    net.addLink(s2, s4, port1=1, port2=2, bw=UPPER_BW, delay=UPPER_DELAY, max_queue_size=QUEUE_SIZE)
    net.addLink(s3, s4, port1=1, port2=3, bw=UPPER_BW, delay=UPPER_DELAY, max_queue_size=QUEUE_SIZE)

    # LINK ACCESSO - S5 (slice LOWER): porta 2 dello switch di accesso, porta j-esima di s5 verso sj
    net.addLink(s1, s5, port1=2, port2=1, bw=LOWER_BW, delay=LOWER_DELAY, max_queue_size=QUEUE_SIZE)
    net.addLink(s2, s5, port1=2, port2=2, bw=LOWER_BW, delay=LOWER_DELAY, max_queue_size=QUEUE_SIZE)
    net.addLink(s3, s5, port1=2, port2=3, bw=LOWER_BW, delay=LOWER_DELAY, max_queue_size=QUEUE_SIZE)

    net.build()
    net.start()

    # disattivo IPv6 poiché Linux genera traffico automatico che sporcherebbe le misure
    info('*** Disattivo IPv6 su host e switch\n')
    for host in net.hosts:
        host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    for sw in net.switches:
        for intf in sw.intfList():
            if intf.name != 'lo':
                sw.cmd('sysctl -w net.ipv6.conf.%s.disable_ipv6=1' % intf.name)

    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = build_network()
    CLI(net)          # apro il prompt mininet>
    net.stop()        # alla fine spengo tutto in modo pulito
