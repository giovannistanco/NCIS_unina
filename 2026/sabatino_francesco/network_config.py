# Inventario della rete: usato sia da topology.py (Mininet) che da controller.py (Ryu)

from collections import deque
from dataclasses import dataclass

ROLE_CLIENT = "client"
ROLE_ATTACKER = "attacker"
ROLE_SERVER = "server"
ROLE_HONEYPOT = "honeypot"


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    mac: str
    dpid: int      # switch a cui è collegato
    port: int      # porta dello switch verso l'host
    role: str


HOSTS = [
    Host("h1", "10.0.0.1", "00:00:00:00:00:01", 1, 1, ROLE_CLIENT),
    Host("h2", "10.0.0.2", "00:00:00:00:00:02", 1, 2, ROLE_CLIENT),
    Host("h3", "10.0.0.3", "00:00:00:00:00:03", 1, 3, ROLE_ATTACKER),
    Host("h4", "10.0.0.4", "00:00:00:00:00:04", 2, 1, ROLE_SERVER),
    Host("h5", "10.0.0.5", "00:00:00:00:00:05", 2, 2, ROLE_HONEYPOT),
    Host("h6", "10.0.0.6", "00:00:00:00:00:06", 3, 3, ROLE_CLIENT),
    Host("h7", "10.0.0.7", "00:00:00:00:00:07", 4, 3, ROLE_ATTACKER),
    Host("h8", "10.0.0.8", "00:00:00:00:00:08", 4, 4, ROLE_CLIENT),
]

# (switch_a, porta_a, switch_b, porta_b) -> anello s1-s3-s2-s4-s1
SWITCH_LINKS = [
    (1, 4, 3, 1),
    (3, 2, 2, 3),
    (2, 4, 4, 1),
    (4, 2, 1, 5),
]

# l'honeypot h5 si finge il server h4
HONEYPOT = "h5"
SERVER = "h4"


class Topology:
    def __init__(self, hosts=HOSTS, links=SWITCH_LINKS):
        self.hosts = {h.name: h for h in hosts}
        self.by_mac = {h.mac: h for h in hosts}
        self.by_ip = {h.ip: h for h in hosts}
        self.edge = {(h.dpid, h.port): h for h in hosts}
        self.honeypot = self.hosts[HONEYPOT]
        self.server = self.hosts[SERVER]

        # adj[a][b] = porta di a verso b
        self.adj = {}
        for a, pa, b, pb in links:
            self.adj.setdefault(a, {})[b] = pa
            self.adj.setdefault(b, {})[a] = pb
        for h in hosts:
            self.adj.setdefault(h.dpid, {})

        # next_hop[(src, dst)] = porta di src da usare per arrivare a dst
        self.next_hop = {}
        for src in sorted(self.adj):
            self._bfs(src)

    def _bfs(self, src):
        # ogni nodo in coda si porta dietro la porta usata per uscire da src
        seen = {src}
        q = deque()
        for nb, port in sorted(self.adj[src].items()):
            seen.add(nb)
            self.next_hop[(src, nb)] = port
            q.append((nb, port))
        while q:
            node, first_port = q.popleft()
            for nb in sorted(self.adj[node]):
                if nb not in seen:
                    seen.add(nb)
                    self.next_hop[(src, nb)] = first_port
                    q.append((nb, first_port))

    def out_port(self, dpid, dst_mac):
        # porta di uscita dello switch dpid per raggiungere dst_mac (None se sconosciuto)
        h = self.by_mac.get(dst_mac)
        if h is None:
            return None
        if h.dpid == dpid:
            return h.port
        return self.next_hop.get((dpid, h.dpid))

    def edge_host(self, dpid, port):
        # host collegato a quella porta, None se è una porta tra switch
        return self.edge.get((dpid, port))

    def host_by_ip(self, ip):
        return self.by_ip.get(ip)
