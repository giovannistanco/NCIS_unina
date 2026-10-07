from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event, switches

#SimpleMonitor13 class inherited SimpleSwitch13 class
class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs) #call constructor of parent's class
        self.datapaths = {} #initialize a data structure to save datapaths of switches to monitor
        self.monitor_thread = hub.spawn(self._monitor) #create a thread for the periodical function _monitor

        self.prev_rx_bytes_dict = {} #dictionary to store previous rx_bytes values for each port in _port_stats_reply_handler
        self.throughput = 0 #throughput every 10s
        self.alarm = False #alarm variable to identify attack
        self.block = False #block variable set where attack source is detected and blocked
        self.threshold = {} #thresholds for each switch's datapath
        self.threshold[1] = 750000  #s1 threshold: 6Mb/s
        self.threshold[2] = 750000  #s2 threshold: 6Mb/s
        self.threshold[3] = 1075000  #s3 threshold: 8.6Mb/s
        self.threshold[4] = 1075000  #s4 threshold: 8.6Mb/s
        self.blocked_list = {} #datapath and port blocked
        self.timer = {} #timers monitoring blocked ports
        self.time_monitor = 10 #interval time of monitoring

    #functions to handle timer
    def set_timer(self, datapath_id, port_no, value):
        self.timer[(datapath_id, port_no)] = value

    def get_timer(self, datapath_id, port_no):
        return self.timer.get((datapath_id, port_no), None)

    #function to update datapath list every time occur a EventOFPStateChange (a switch connects/disconnects itself to the controller)
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    #function that every 10s issue a request to switch saved in datapath to acquire statistical information
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.time_monitor)
            if self.block is True:
                self.block = False
                self.prev_rx_bytes_dict = {}
                hub.sleep(50)

    #function called every 10s to every switches in datapath by _monitor function
    #OFPFlowStatsRequest and OFPPortStatsRequest are issued to the switch
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    #function that receive and handle OFPFlowStatsReply events
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ------------------ '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                              flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    #function that receive and handle OFPPortStatsReply events
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error '
                         'throughput alarm')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- -------- '
                         '-------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):

            datapath = ev.msg.datapath #datapath switch under analysis
            datapath_id = ev.msg.datapath.id
            port_no = stat.port_no #port under analysis
            rx_bytes = stat.rx_bytes #rx_bytes related to port under analysis
            if datapath_id not in self.prev_rx_bytes_dict:
                self.prev_rx_bytes_dict[datapath_id] = {}
            #save throughput if it's present a previous value of rx_bytes for this port and datapath_id
            if port_no in self.prev_rx_bytes_dict[datapath_id]:
                self.throughput = (rx_bytes - self.prev_rx_bytes_dict[datapath_id][port_no])/10

                #raise an alarm if throughput exceeds the defined threshold and call function _block_attack
                value_timer = self.get_timer(datapath_id, port_no)
                if value_timer is None: 
                    if self.block is False:
                        if self.throughput > self.threshold[datapath_id]:
                            self.alarm = True #attack detected
                            self.set_timer(datapath_id, port_no, 10)
                            self._block_attack(datapath, port_no)
                        else:
                            self.alarm = False
                else:
                    value_timer_new = value_timer - 10
                    if value_timer_new <= 0:
                        if self.throughput > self.threshold[datapath_id]:
                            #still (or again) above threshold: confirm/renew this port's own
                            #block for another 90s. No other switch's port is touched here -
                            #each port is judged only on its own rx counter, which is exactly
                            #what lets a downstream switch (e.g. s3) release itself once the
                            #upstream one (e.g. s1) has actually stopped forwarding the flood,
                            #instead of racing it and possibly winning by mistake.
                            self.block = True
                            self.alarm = True
                            self.set_timer(datapath_id, port_no, 90)
                        else:
                            #throughput back under threshold: release the port for good
                            if datapath_id in self.blocked_list and port_no in self.blocked_list[datapath_id]:
                                self.remove_table_flow(datapath_id, port_no)
                            self.timer.pop((datapath_id, port_no), None)
                            self.alarm = False
                    else:
                        #still counting down (covers both the initial 10s window and the
                        #extended 90s one): save the decremented value
                        self.set_timer(datapath_id, port_no, value_timer_new)


            self.prev_rx_bytes_dict[datapath_id][port_no] = rx_bytes #update previous value of rx_bytes for this port

            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d %8d %8s',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                            self.throughput, self.alarm)

    def _block_attack(self, datapath, port_no):
        print(f"Blocking datapath: {datapath.id} with port number: {port_no}")
        if datapath.id in self.blocked_list:
            self.blocked_list[datapath.id].append(port_no)
        else:
            self.blocked_list[datapath.id] = [port_no]

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [] #drop the packet
        priority = 2 #other rules have priority 1
        match = ofp_parser.OFPMatch(in_port=port_no)
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask, table_id, ofp.OFPFC_ADD, idle_timeout, hard_timeout,
                                    priority, ofp.OFP_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, ofp.OFPFF_SEND_FLOW_REM, match, inst)
        datapath.send_msg(req)

    def remove_table_flow(self, datapath_id, port_no):
        print(f"Unblocking datapath: {datapath_id} with port number: {port_no}")

        self.blocked_list[datapath_id].remove(port_no)

        ofp = self.datapaths[datapath_id].ofproto
        ofp_parser = self.datapaths[datapath_id].ofproto_parser
        match = ofp_parser.OFPMatch(in_port=port_no)
        req = ofp_parser.OFPFlowMod(datapath=self.datapaths[datapath_id], table_id=0, command=ofp.OFPFC_DELETE_STRICT, priority=2,
                                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match)

        self.datapaths[datapath_id].send_msg(req)