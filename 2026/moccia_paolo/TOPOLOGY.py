from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink

# Indirizzo e porta del controller Ryu.
CTRL_IP = '127.0.0.1'
CTRL_PORT = 6653

BW_ACCESS = 10   
BW_CORE = 20     
BW_SERVER = 10   

class Environment(object):

    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController,
                                    ip=CTRL_IP, port=CTRL_PORT)
        c1.start()

        info("*** Adding hosts and switches\n")
        #Host
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')  
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24')  
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3/24')  
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4/24')  

        #Switch
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')

        info("*** Adding links\n")
        #Link
        self.net.addLink(self.h1, self.s1, port1=0, port2=1,
                         bw=BW_ACCESS, delay='0.1ms')
        self.net.addLink(self.h2, self.s1, port1=0, port2=2,
                         bw=BW_ACCESS, delay='0.1ms')
        self.net.addLink(self.h3, self.s2, port1=0, port2=1,
                         bw=BW_ACCESS, delay='0.1ms')
        self.net.addLink(self.h4, self.s4, port1=0, port2=2,
                         bw=BW_SERVER, delay='0.1ms')

        self.net.addLink(self.s1, self.s3, port1=3, port2=1,
                         bw=BW_CORE, delay='1ms')
        self.net.addLink(self.s2, self.s3, port1=3, port2=2,
                         bw=BW_CORE, delay='1ms')
        self.net.addLink(self.s3, self.s4, port1=3, port2=1,
                         bw=BW_CORE, delay='1ms')

        info("*** Starting network\n")
        self.net.build()
        self.net.start()

if __name__ == '__main__':

    setLogLevel('info')

    info('starting the environment\n')
    env = Environment()
    

    info("*** Running CLI\n")
    CLI(env.net)
    env.net.stop()
