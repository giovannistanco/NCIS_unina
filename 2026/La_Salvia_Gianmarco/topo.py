from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def build():
    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)
    net.addController('c0', ip='127.0.0.1', port=6653)

    s1, s2, s3, s4 = [net.addSwitch(f's{i}', protocols='OpenFlow13') for i in range(1, 5)]

    h1 = net.addHost('h1', ip='10.0.0.1/24')   # legittimo
    h2 = net.addHost('h2', ip='10.0.0.2/24')   # attaccante 1
    h3 = net.addHost('h3', ip='10.0.0.3/24')   # legittimo
    h4 = net.addHost('h4', ip='10.0.0.4/24')   # attaccante 2
    h5 = net.addHost('h5', ip='10.0.0.5/24')   # server

    # accesso
    net.addLink(h1, s1, bw=100); net.addLink(h2, s1, bw=100)
    net.addLink(h3, s2, bw=100); net.addLink(h4, s2, bw=100)
    # dorsale
    net.addLink(s1, s3, bw=50);  net.addLink(s2, s3, bw=50)
    net.addLink(s3, s4, bw=20)                 # collo di bottiglia
    net.addLink(s4, h5, bw=100)

    net.start()
    h5.cmd('python3 -m http.server 80 &')      # server web
    h5.cmd('iperf -s &')                       # server iperf TCP
    h5.cmd('iperf -s -u &')                    # server iperf UDP
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build()