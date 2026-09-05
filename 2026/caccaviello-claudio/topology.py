"""
TOPOLOGIA, e' molto piu' chiara nel ppt

    h1 (video)  --\
    h2 (iot)    ---  s1 ===[collo di bottiglia]=== s2 --- srv
    h3 (bulk)   --/

Comandi :
    sudo python3 topology.py --qos slicing
    sudo python3 topology.py --qos none
"""

import argparse
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

#PARAMETRI COSTANTI

CTRL_IP = '127.0.0.1'  #Ip e port del controller
CTRL_PORT = 6653

BOTTLENECK_MBIT = 10        # capacita' del link s1-s2, che è il collo di bottiglia, lo metto abbastanza basso in modo da saturarsi
ACCESS_DELAY = '5ms'        # ritardo dei link di accesso
ACCESS_JITTER = '1ms'

# porta di s1 che affaccia sul collo di bottiglia (l'ultima aggiunta)
BOTTLENECK_PORT = 4

# Definizione degli slice.

#   queue_id   -> identificatore usato da OFPActionSetQueue nel controller
#   min_mbit   -> banda garantita
#   max_mbit   -> tetto massimo


# La coda 0 e' quella di default: ci finisce tutto il traffico
# non classificato, incluso il bulk.

SLICES = {
    0: {'nome': 'bulk',  'min_mbit': 1, 'max_mbit': BOTTLENECK_MBIT},
    1: {'nome': 'video', 'min_mbit': 4, 'max_mbit': BOTTLENECK_MBIT},
    2: {'nome': 'iot',   'min_mbit': 2, 'max_mbit': BOTTLENECK_MBIT},
}

#Code


def _mbit(v):  #Semplicemente per convertire megabit al secondo in bit al secondo voluti da OpenvSwitch
    return int(v * 10 ** 6)


def configura_code(switch, porta, code):
    """Installa una QoS linux-htb sull'interfaccia indicata.

    `code` e' un dizionario {queue_id: {'min_mbit':..., 'max_mbit':...}}.
    Con una sola voce si ottiene il caso baseline: stesso meccanismo di
    rate limiting, nessuna differenziazione.
    """
    intf = '%s-eth%d' % (switch.name, porta)

    riferimenti = ','.join('%d=@q%d' % (qid, qid) for qid in sorted(code))      #Produce 0=@q0,1=@q1,2=@q2.
    cmd = [
        'ovs-vsctl',
        '-- set Port %s qos=@newqos' % intf,
        '-- --id=@newqos create QoS type=linux-htb',
        'other-config:max-rate=%d' % _mbit(BOTTLENECK_MBIT),
        'queues=%s' % riferimenti,
    ]
    for qid in sorted(code):
        c = code[qid]
        cmd.append(
            '-- --id=@q%d create Queue '
            'other-config:min-rate=%d other-config:max-rate=%d'
            % (qid, _mbit(c['min_mbit']), _mbit(c['max_mbit']))
        )

    switch.cmd(' '.join(cmd))
    info('*** QoS installata su %s\n' % intf)
    for qid in sorted(code):
        c = code[qid]
        info('      coda %d (%-5s)  min %2d Mbps  max %2d Mbps\n'
             % (qid, c.get('nome', '-'), c['min_mbit'], c['max_mbit']))


def pulisci_code(switch):
    """Rimuove QoS e Queue orfane: OVS non le cancella da solo."""
    switch.cmd('ovs-vsctl --all destroy QoS')
    switch.cmd('ovs-vsctl --all destroy Queue')


#Rete


def costruisci(modo_qos):
    net = Mininet(controller=None, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=True, cleanup=True)

    info('*** Controller remoto %s:%d\n' % (CTRL_IP, CTRL_PORT))
    net.addController('c0', controller=RemoteController,
                      ip=CTRL_IP, port=CTRL_PORT)

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    srv = net.addHost('srv', ip='10.0.0.100/24')

    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    # Link di accesso: ritardo e jitter, nessun limite di banda.
    # Sono interfacce diverse da quella del collo di bottiglia,
    # quindi il qdisc di TCLink non interferisce con la QoS di OVS.
    for h, porta in ((h1, 1), (h2, 2), (h3, 3)):
        net.addLink(h, s1, port2=porta,
                    delay=ACCESS_DELAY, jitter=ACCESS_JITTER, use_htb=True)

    # Collo di bottiglia: link nudo, la capacita' la impone la QoS.
    net.addLink(s1, s2, port1=BOTTLENECK_PORT, port2=1)
    net.addLink(s2, srv, port1=2)

    net.start()

    pulisci_code(s1)
    if modo_qos == 'slicing':
        configura_code(s1, BOTTLENECK_PORT, SLICES)
    else:
        info('*** Modalita\' baseline: coda unica, nessuna differenziazione\n')
        configura_code(s1, BOTTLENECK_PORT,
                       {0: {'nome': 'unica', 'min_mbit': 1,
                            'max_mbit': BOTTLENECK_MBIT}})

    info('\n*** Verifica delle code installate:\n')
    info(s1.cmd('ovs-vsctl list queue') or '')

    return net


def main():
    p = argparse.ArgumentParser(description='Topologia per service slicing SDN')
    p.add_argument('--qos', choices=['none', 'slicing'], default='slicing',
                   help='none = coda unica (baseline), slicing = tre code')
    args = p.parse_args()

    setLogLevel('info')
    net = costruisci(args.qos)

    info('\n*** Rete pronta. Il controller Ryu deve essere gia\' in ascolto.\n')
    info('*** Prova: h1 ping srv\n\n')
    CLI(net)

    pulisci_code(net.get('s1'))
    net.stop()


if __name__ == '__main__':
    main()
