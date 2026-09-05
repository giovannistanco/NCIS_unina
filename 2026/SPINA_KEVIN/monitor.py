from ryu.lib import hub
import time

class TrafficMonitor:

    def __init__(self, controller):
        print("TRAFFIC MONITOR CREATO")
        # riferimento al controller Ryu principale
        self.controller = controller

        # qui salveremo le letture precedenti delle porte
        self.port_stats_prev = {}

        # qui salveremo il carico dei link
        # (src_switch, dst_switch) -> Mbps
        self.link_load = {}

        # intervallo di monitoraggio
        self.monitor_interval = 2

        #creazione del thread di monitoraggio
        self.monitor_thread = hub.spawn(self._monitor)

        self.link_capacity = 10.0       # Mbps
        self.congestion_threshold = 0.70

    def _monitor(self):

        while True:
            #facciamo inviare ogni intervallo una richiasta a TUTTI gli switch delle statische
            for datapath in list(self.controller.datapaths.values()):
                self._request_port_stats(datapath)

            hub.sleep(self.monitor_interval)

    def _request_port_stats(self, datapath):
    #funzione che richiede le statistiche a tutte le p[orte di quello switch

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(
            datapath,
            0,#flag
            ofproto.OFPP_ANY#statistiche di tutte le porte
        )

        datapath.send_msg(req)

    def handle_port_stats(self, msg):

        datapath = msg.datapath
        dpid = datapath.id
        now = time.monotonic()#salviamo istante attuale
    #msg.body contine una statistica per ogni porta, le vediamo tutte
        for stat in msg.body:
            #v utile per capipre che link stiamo guardando
            dst_switch = None

    # cerco se questa porta porta verso un altro switch, ricorda links (dpid, dpid)-> porta che li colelga
            for (src, dst), port_no in self.controller.links.items():

                if src == dpid and port_no == stat.port_no:
                    dst_switch = dst
                    break

            # se è una porta host o LOCAL non ci interessa
            if dst_switch is None:
                continue#prossima stat

            key = (dpid, stat.port_no)#chiave switch, porta

            #vediamo se abbiamo gia una lettura per quella porta
            previous = self.port_stats_prev.get(key)

            # dalla seconda lettura in poi posso calcolare il bitrate
            if previous is not None:
                
                previous_tx_bytes, previous_time = previous
                #calcolo del bit rate
                delta_bytes = stat.tx_bytes - previous_tx_bytes
                delta_time = now - previous_time

                if delta_time > 0 and delta_bytes >= 0:

                    Mbps = (delta_bytes * 8) / (delta_time * 1_000_000)
                    #*1000000 per avere i Mbit
                    self.link_load[(dpid, dst_switch)] = Mbps

                    #print(
                     #   "LINK s%s -> s%s: %.3f Mbps"
                     #   % (dpid, dst_switch, Mbps)
                    #)

            # salvo la lettura corrente per il prossimo giro
            self.port_stats_prev[key] = (stat.tx_bytes, now)

    def get_path_load(self, path):
            #funzione che, dato un path, restituisce il load del link più carico
            max_load = 0.0

            for i in range(len(path) - 1):

                src = path[i]
                dst = path[i + 1]
                #get((src,dst), 0,0) da 0 se non abbiamo statistiche per quel link
                load = self.link_load.get((src, dst), 0.0)

                if load > max_load:
                    max_load = load

            return max_load

    def is_path_congested(self, path):
        #funzione che verifica se quel path e soprasoglia e quindi congestionato
        path_load = self.get_path_load(path)

        utilization = path_load / self.link_capacity

        return utilization >= self.congestion_threshold






