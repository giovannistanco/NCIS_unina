#!/bin/bash

# Configurazione QoS della topologia attuale.
#
# Ogni porta usa HTB con capacità massima 10 Mbps:
#   Queue 0 = BEST_EFFORT -> minimo 4 Mbps, priorità 2
#   Queue 1 = HIGH        -> minimo 6 Mbps, priorità 1
#
# Le porte interne s1, s2, s3, s4 non vengono configurate:
# ci interessano solo le porte reali sX-ethY.

PORTS=(

    s1-eth4
    s1-eth5
    s1-eth6

    s2-eth1
    s2-eth2

    s3-eth1
    s3-eth2

    s4-eth1
    s4-eth3
    s4-eth4

    s5-eth1
    s5-eth2

    s6-eth1
    s6-eth2
)

for port in "${PORTS[@]}"
do
    echo "Configuro QoS sulla porta $port..."

    ovs-vsctl \
        -- set Port "$port" qos=@qos \
        -- --id=@qos create QoS \
            type=linux-htb \
            other-config:max-rate=10000000 \
            queues:0=@be \
            queues:1=@high \
        -- --id=@be create Queue \
            other-config:min-rate=4000000 \
            other-config:priority=2 \
        -- --id=@high create Queue \
            other-config:min-rate=6000000 \
            other-config:priority=1
done

echo "Configurazione QoS completata."
