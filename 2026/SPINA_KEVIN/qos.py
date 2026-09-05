class QoSManager:

    HIGH = "HIGH"
    BEST_EFFORT = "BEST_EFFORT"

    #id delle code:
    HIGH_QUEUE = 1
    BEST_EFFORT_QUEUE = 0

    def __init__(self):

        # set con i servizi autorizzati a ricevere QoS HIGH
        # (IP sorgente, porta sorgente)
        self.high_services = {
            ("10.0.0.1", 5000),
        }

        # SLA della classe HIGH
        self.high_sla_mbps = 2.0

        # soglia hard QoS
        self.hard_threshold = 0.95


    def classify_flow(self, flow_id):
        #funzione per classificare il traffico in base alle info mantenute dal manager
        # traffico che non è TCP/UDP -> BE
        if flow_id is None or len(flow_id) != 5:#!=5 per ICMP che ha sono srcip e dstip
            return self.BEST_EFFORT

        src_ip = flow_id[0]
        src_port = flow_id[3]

        if (src_ip, src_port) in self.high_services:
            return self.HIGH

        return self.BEST_EFFORT
    
    def get_queue_id(self, qos_class):

        if qos_class == self.HIGH:
            return self.HIGH_QUEUE

        return self.BEST_EFFORT_QUEUE







