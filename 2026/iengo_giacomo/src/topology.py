from mininet.log import setLogLevel, info
from mininet.net import Mininet, CLI
from mininet.link import TCLink
from mininet.node import RemoteController, Node
from mininet.term import makeTerm
from mininet.node import OVSKernelSwitch

import os
from datetime import datetime
from time import sleep


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DNS_DIR =  os.path.join(BASE_DIR, 'dns', 'hosts.txt')
WEB_DIR =  os.path.join(BASE_DIR, 'web')

timestamp = lambda : f"{datetime.now().strftime('%H:%M:%S')}.{datetime.now().microsecond // 1000:03d}"

setLogLevel('info')
OVSKernelSwitch.setup()

net = Mininet(controller=RemoteController, link=TCLink)
r1 = net.addHost('r1', cls=Node, ip=None)
r2 = net.addHost('r2', cls=Node, ip=None)
info(f"[{timestamp()}] Routers added\n")


dns  =       net.addHost('dns',       mac ='00:00:00:00:01:01', ip='192.168.1.1/24', defaultRoute='via 192.168.1.254')
db   =       net.addHost('db',        mac ='00:00:00:00:01:02', ip='192.168.1.2/24', defaultRoute='via 192.168.1.254')
web  =       net.addHost('web',       mac ='00:00:00:00:01:03', ip='192.168.1.3/24', defaultRoute='via 192.168.1.254')
ws1  =       net.addHost('ws1',       mac ='00:00:00:00:02:01', ip='192.168.2.1/24', defaultRoute='via 192.168.2.254')
ws2  =       net.addHost('ws2',       mac ='00:00:00:00:02:02', ip='192.168.2.2/24', defaultRoute='via 192.168.2.254')
user =       net.addHost('user',      mac ='00:00:00:01:01:01', ip='192.168.1.1/24',  defaultRoute='via 192.168.1.254')
info(f"[{timestamp()}] Hosts added\n")

s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
info(f"[{timestamp()}] OF-Switches added\n")

net.addLink(dns, s1)
net.addLink(db, s1)
net.addLink(web, s1)
net.addLink(ws1, s2)
net.addLink(ws2, s2)
net.addLink(s1, r1, intfName2='eth1', addr2='00:00:00:00:ff:01')
net.addLink(s2, r1, intfName2='eth2', addr2='00:00:00:00:ff:02')
net.addLink(r1, r2, intfName1='eth0', addr1='00:00:00:00:ff:00', intfName2='eth0', addr2='00:00:00:01:ff:00')
net.addLink(user, r2, intfName2='eth1', addr2='00:00:00:01:ff:01')
info(f"[{timestamp()}] Links added\n")



ctl = net.addController('ctl', controller=RemoteController, ip='127.0.0.1', port=6653)
info(f"[{timestamp()}] Controller added\n")


net.build()
info(f"[{timestamp()}] Net built\n")

# ================= R1 =================
# make it a router
r1.cmd('sysctl net.ipv4.ip_forward=1')
# assign ip to interfaces
r1.cmd('ifconfig eth2 192.168.2.254/24 up')
r1.cmd('ifconfig eth1 192.168.1.254/24 up')
r1.cmd('ifconfig eth0 87.23.3.41/30 up')
# virtual local routes
r1.cmd('ip route add 192.168.10.0/24 dev eth1')
r1.cmd('ip route add 192.168.20.0/24 dev eth2')

# Demilitarize s1 subnet
# Host 192.168.1.1 is reachable at 143.225.1.1
r1.cmd('iptables -t nat -A PREROUTING -d 143.225.1.1 -j DNAT --to-destination 192.168.1.1')
r1.cmd('iptables -t nat -A POSTROUTING -s 192.168.1.1 -j SNAT --to-source 143.225.1.1')
# # Host 192.168.1.2 is reachable at 143.225.1.2
# r1.cmd('iptables -t nat -A PREROUTING -d 143.225.1.2 -j DNAT --to-destination 192.168.1.2')
# r1.cmd('iptables -t nat -A POSTROUTING -s 192.168.1.2 -j SNAT --to-source 143.225.1.2')
# # Host 192.168.1.3 is reachable at 143.225.1.3
# r1.cmd('iptables -t nat -A PREROUTING -d 143.225.1.3 -j DNAT --to-destination 192.168.1.3')
# r1.cmd('iptables -t nat -A POSTROUTING -s 192.168.1.3 -j SNAT --to-source 143.225.1.3')

# Militarize s2 subnet
# Hosts in subnet s2 sit behind NAT
r1.cmd('iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o eth0 -j SNAT --to-source 87.23.3.41')

# virtual public routes
r1.cmd('ip route add 143.225.10.0/24 dev eth1')



# ================= R2 =================
# make it a router
r2.cmd('sysctl net.ipv4.ip_forward=1')
# assign ip to interfaces
r2.cmd('ifconfig eth1 192.168.1.254/24 up')
r2.cmd('ifconfig eth0 87.23.3.42/30 up')
# BGP routes published by R1 had effect in R2
r2.cmd('ip route add 143.225.1.0/24  via 87.23.3.41 dev eth0')
r2.cmd('ip route add 143.225.10.0/24 via 87.23.3.41 dev eth0')
# Hosts of R2 sit behind NAT
r2.cmd('iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 87.23.3.42')


net.start()
info(f"[{timestamp()}] Net started\n")


dns.cmd(f'dnsmasq -q -R -z --user=root -H {DNS_DIR} -a 192.168.1.1')
web.cmd(f'cd {WEB_DIR} && python3 -m http.server 80 &')
db.cmd('redis-server --bind 0.0.0.0 --port 6379 --protected-mode no &')
web.cmd('id -u webuser &>/dev/null || useradd -m -s /bin/bash webuser')
web.cmd('echo "webuser:webuser" | chpasswd')
web.cmd('mkdir -p /var/run/sshd')
web.cmd('/usr/sbin/sshd -o PidFile=/tmp/web_sshd.pid -o PasswordAuthentication=yes -o AllowUsers=webuser &')



for h in [db, web, ws1, ws2]:
    h.cmd(f'echo "nameserver 192.168.1.1" > /tmp/{h.name}_resolv.conf')
    h.cmd(f'mount --bind /tmp/{h.name}_resolv.conf /etc/resolv.conf')
user.cmd('echo "nameserver 143.225.1.1" > /tmp/user_resolv.conf')
user.cmd('mount --bind /tmp/user_resolv.conf /etc/resolv.conf')

info(f"[{timestamp()}] Started all services\n")



# makeTerm(web)
# makeTerm(db)

# =================== TEST DB ====================================
# ws1.cmd('redis-cli -h db.lan -p 6379 ping')                       # expected: PONG
# ws1.cmd('redis-cli -h db.lan -p 6379 set mykey "MTD_is_awesome"') # expected: OK
# ws1.cmd('redis-cli -h db.lan -p 6379 get mykey')                  # expected: "MTD_is_awesome"




info(f"[{timestamp()}] Returning CLI...\n")
CLI(net)

dns.cmd('pkill dnsmasq')
web.cmd('pkill -f "python3 -m http.server"')
web.cmd('kill $(cat /tmp/web_sshd.pid)')
db.cmd('pkill redis-server')
web.cmd('userdel -r -f webuser')
r1.cmd('iptables -t nat -F')
r2.cmd('iptables -t nat -F')
r1.cmd('sysctl net.ipv4.ip_forward=0')
r2.cmd('sysctl net.ipv4.ip_forward=0')
for h in [db, web, ws1, ws2, user]:
    h.cmd(f'rm -f /tmp/{h.name}_resolv.conf')
info(f"[{timestamp()}] Cleaned up services and rules\n")
net.stop()