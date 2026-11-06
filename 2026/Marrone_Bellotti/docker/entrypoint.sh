#!/bin/bash
# Avvia i demoni Open vSwitch dentro il container (niente systemd qui).
# Mininet usa ovs-vsctl, che richiede ovsdb-server + ovs-vswitchd attivi.
set -e

mkdir -p /var/run/openvswitch /etc/openvswitch

if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db \
        /usr/share/openvswitch/vswitch.ovsschema
fi

# ovsdb-server (se non già attivo)
if ! ovs-vsctl --timeout=2 show >/dev/null 2>&1; then
    ovsdb-server /etc/openvswitch/conf.db \
        --remote=punix:/var/run/openvswitch/db.sock \
        --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
        --pidfile --detach --log-file >/dev/null 2>&1
    ovs-vsctl --no-wait init
    ovs-vswitchd --pidfile --detach --log-file >/dev/null 2>&1
fi

# Pulisce eventuali residui di Mininet da run precedenti
mn -c >/dev/null 2>&1 || true

exec "$@"
