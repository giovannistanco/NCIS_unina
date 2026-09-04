from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import udp
from os_ken.lib.packet import arp
from dnslib import DNSRecord, QTYPE, A

from os_ken.lib import hub
import random
import socket
import struct
from datetime import datetime


from eventlet import tpool

from pprint import pformat

class MTD(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    pubToPriv = {
        '143.225.1.2': '192.168.1.2',
        '143.225.1.3': '192.168.1.3'
    }

    ipRanges = {
        '192.168.1.2': ('192.168.10.1', '192.168.10.127'),    # db
        '192.168.1.3': ('192.168.10.128', '192.168.10.253'),  # web
        '192.168.2.1': ('192.168.20.1', '192.168.20.127'),    # ws1
        '192.168.2.2': ('192.168.20.128', '192.168.20.253'),  # ws2
        '143.225.1.2': ('143.225.10.1', '143.225.10.127'),    # db  (public)
        '143.225.1.3': ('143.225.10.128', '143.225.10.253'),  # web (public)
    }

    rotationInterval = 15
    logCategoryJustify = 12


    def __init__(self, *args, **kwargs):
        super(MTD, self).__init__(*args, **kwargs)
        
        self.macTable = {}
        self.arpTable = {}
        self.vips = {}
        self.rips = {}
        self.oldVipToMac = {}

        self._rotateVips()
        self.rotationThread = hub.spawn(self._rotationLoop)
        self.dumpThread     = hub.spawn(self._dumpOnEnter)
        

    def _dumpOnEnter(self):
        while True:
            tpool.execute(input)

            self._log('info', 'Dump State', 'Dumping state...')
            self.logger.info("\033[31m" + f"macTable = {pformat(self.macTable, compact=False)}"       + "\033[0m")
            self.logger.info("\033[31m" + f"arpTable = {pformat(self.arpTable, compact=False)}"       + "\033[0m")
            self.logger.info("\033[31m" + f"pubToPriv = {pformat(self.pubToPriv, compact=False)}"     + "\033[0m")
            self.logger.info("\033[31m" + f"vips = {pformat(self.vips, compact=False)}"               + "\033[0m")
            self.logger.info("\033[31m" + f"rips = {pformat(self.rips, compact=False)}"               + "\033[0m")
            self.logger.info("\033[31m" + f"oldVipToMac = {pformat(self.oldVipToMac, compact=False)}" + "\033[0m")

        

    def _rotationLoop(self):
        while True:
            hub.sleep(self.rotationInterval)
            self._rotateVips()

    def _rotateVips(self):
        newVips = {}
        
        for realIp, (lBound, rBound) in self.ipRanges.items():
            lBu = struct.unpack("!I", socket.inet_aton(lBound))[0]
            rBu = struct.unpack("!I", socket.inet_aton(rBound))[0]
            newVip = random.randint(lBu, rBu)
            newVips[realIp] = socket.inet_ntoa(struct.pack("!I", newVip))
        
        newRips = {v: k for k, v in newVips.items()}

        self.vips = newVips
        self.rips = newRips
                          
        self._log('info', 'MTD Rotation', "Rotated Virtual IPs")


    def _log(self, level, category, message):
            now = datetime.now()
            timestamp = f"{now.strftime('%H:%M:%S')}.{now.microsecond // 1000:03d}"
            out = f"[{timestamp}][{category.ljust(self.logCategoryJustify)}]: {message}"
            
            if   level == 'info'   : self.logger.info(out)
            elif level == 'warning': self.logger.warning(out)
            else                   : self.logger.info(out)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flowRemovedHandler(self, ev):
        msg = ev.msg
        match = msg.match

        # Only the expiration of In Bound Ip translation rules will trigger this function
        expVip = match['ipv4_dst'] # expired Vip
        srcRip = match['ipv4_src'] # the real ip that requested the translation

        self.oldVipToMac[expVip]['src'].discard(srcRip)
        self._log('info', 'vIP history', f"Tr. rule expired, {srcRip} cannot reach the old vIP {expVip} anymore")
        if len(self.oldVipToMac[expVip]['src']) == 0:
            del self.oldVipToMac[expVip]
            self._log('info', 'vIP history', f"Old vIP {expVip} has been forgotten")


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switchFeaturesHandler(self, ev):
        datapath = ev.msg.datapath 
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser
        self._log('info', 'Setup', f"New OF-Switch connected with dpid: {datapath.id}")
        
        # Intercept Table Misses
        self.addFlow(
            datapath,
            0,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Intercept IPv4 Traffic from Router eth1
        self.addFlow(
            datapath,
            5,
            parser.OFPMatch(eth_type=0x0800, eth_src='00:00:00:00:ff:01'),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Intercept IPv4 Traffic from Router eth2
        self.addFlow(
            datapath,
            5,
            parser.OFPMatch(eth_type=0x0800, eth_src='00:00:00:00:ff:02'),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Intercept ARP Packets
        self.addFlow(
            datapath,
            100,
            parser.OFPMatch(eth_type=0x0806),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Intercept DNS Queries
        self.addFlow(
            datapath,
            100,
            parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=53),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Intercept DNS Answers
        self.addFlow(
            datapath,
            100,
            parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=53),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Block ICMP Redirects (Type 5) to prevent Hairpin routing bypass
        self.addFlow(
            datapath,
            100,  # High priority to ensure it overrides normal forwarding
            parser.OFPMatch(eth_type=0x0800, ip_proto=1, icmpv4_type=5),
            []    # Empty actions list = Drop
        )

    def addFlow(self, datapath, priority, match, actions, idleTimeout=0, notifyOnIdleExpiration=False):
        # we don't actually need buffer_id in this implemenation of MTD
        # we surely need idle_timeout, which, if equal to N, the flow rule will live N seconds
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flags = ofproto.OFPFF_SEND_FLOW_REM if notifyOnIdleExpiration else 0

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            idle_timeout=idleTimeout,
            flags=flags,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packetInHandler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        inPort = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        ethPkt = pkt.get_protocol(ethernet.ethernet)
        
        if not ethPkt or ethPkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self._learnMACTable(datapath, ethPkt, inPort)
        
        # Handle ARP
        arpPkt = pkt.get_protocol(arp.arp)
        if arpPkt: # if it is an arp packet
            self._learnARPTable(arpPkt.src_ip, ethPkt.src)
            if arpPkt.opcode == arp.ARP_REQUEST: # if it is a request

                if arpPkt.dst_ip in self.rips or arpPkt.dst_ip in self.oldVipToMac: # if it asks for a virtual IP
                    self.spoofArpRequestForVirtualIp(datapath, inPort, ethPkt, arpPkt) # spoof the answer, and send it back a reply
                    return # drop
                        
                if (arpPkt.dst_ip in self.vips and                            # if it asks for a real IP of the virtual ones (the MTD protected hosts)
                   ethPkt.src not in ('00:00:00:00:ff:01', '00:00:00:00:ff:02', '00:00:00:00:01:01')): # and, is not originated by the router or dns
                   self._log('info', 'Deny Real IP', f"Blocked ARP Request for rIP {arpPkt.dst_ip} from {arpPkt.src_ip}")
                   return # drop
                    

        # Handle IP translation            
        ipPkt = pkt.get_protocol(ipv4.ipv4)
        if ipPkt and ipPkt.dst in self.rips and ethPkt.src in ('00:00:00:00:ff:01', '00:00:00:00:ff:02'): # if the destination is virtual and the source is the router
            if self.rips[ipPkt.dst] in self.pubToPriv:
                self.installPublicInOutboundTranslation(datapath, inPort, pkt, ethPkt, ipPkt, msg)
            else:
                self.installPrivateInboundTranslation(datapath, inPort, pkt, ethPkt, ipPkt, msg)
            return

        
        # Deny realIP -> realIP communications
        udpPkt = pkt.get_protocol(udp.udp)
        if (ipPkt and ipPkt.dst in self.vips and # if the destination is real IP of the virtual ones (the MTD protected hosts)
            not (udpPkt and ipPkt.src == '192.168.1.1' and udpPkt.src_port == 53)): # and is not a DNS reply to them
            self._log('info', 'Deny Real IP', f"Blocked direct IPv4 to rIP {ipPkt.dst} from {ipPkt.src}")
            self.addFlow(
                datapath, 
                50, 
                datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=ipPkt.dst), 
                [], 
                idleTimeout=10
            )
            return # block it now and for the next 10 seconds with an hardware rule

        # Firewall on the DNS
        if (ipPkt and (ipPkt.dst == '192.168.1.1' or ipPkt.src == '192.168.1.1') and # if an ip packet is sent by or destinated to DNS
            not (udpPkt and (udpPkt.dst_port == 53 or udpPkt.src_port == 53))):      # and it's not an udp packet on port 53
            self._log('info', 'DNS Firewall', f"Blocked unauthorized IPv4 (Proto: {ipPkt.proto}) involving DNS server")
            return # drop

        # Handle DNS
        dnsPkt = self._get_dns_protocol(pkt)
        if (dnsPkt and dnsPkt.header.qr == 1  # if it is a DNS answer
            and any(str(answer.rdata) in self.vips for answer in dnsPkt.rr if answer.rtype == QTYPE.A)): # it's answering for a real ip
                self.rewriteDnsAnswerForVirtualIp(datapath, pkt, ethPkt, ipPkt, dnsPkt)
                return
        
        self.handleNormalForwarding(datapath, inPort, ethPkt, msg)


    def spoofArpRequestForVirtualIp(self, datapath, inPort, ethPkt, arpPkt) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        dstVip = arpPkt.dst_ip
        srcRip = arpPkt.src_ip
        srcMac = arpPkt.src_mac

        if dstVip in self.rips:
            dstRip = self.rips[dstVip]
            if dstRip in self.pubToPriv:
                dstRip = self.pubToPriv[dstRip]
            dstMac = self.arpTable.get(dstRip)

            if not dstMac:
                self._log('info', 'ARP handler', f"MAC for {dstRip} unknown. Probing and dropping arp request for {dstVip}.")
                self._probeMAC(datapath, dstRip)
                return
                # why we actually drop the packet here? leaving the ARP request's handling mid-air?
                # because we probe the MAC that we dont already have, and we leverage the OS mechanism of ARP
                # retransmission in case of an unreplied ARP request. So this same arp request will be reissued
                # identically in about a split second by the same sender.
        
        else: # (dstVip is in self.oldVipToMac)
            dstMac = self.oldVipToMac[dstVip]['mac']

        newPkt = packet.Packet()
        newPkt.add_protocol(ethernet.ethernet(
            dst=srcMac,
            src=dstMac,
            ethertype=ethPkt.ethertype
        ))
        newPkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dstMac,
            src_ip=dstVip,
            dst_mac=srcMac,
            dst_ip=srcRip
        ))
        newPkt.serialize()

        self._log('info', 'ARP handler', f"Rewrote ARP response {dstVip} -> {dstMac}")

        actions = [parser.OFPActionOutput(inPort)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=newPkt.data
        )
        datapath.send_msg(out)


    def installPrivateInboundTranslation(self, datapath, inPort, pkt, ethPkt, ipPkt, msg) -> None:
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        dstLanVip = ipPkt.dst
        srcLanRip = ipPkt.src
        dstLanRip = self.rips[dstLanVip]
        srcLanVip = self.vips[srcLanRip]


        # Here we are sure that port <-> mac corrispondence exists because
        # if the router has sent a packet to a virtual ip, it means that has already asked before,
        # with an ARP request: Who has this virtual IP? So our arp arp request spoofer has already replied to that,
        # and if that's happened, the real_ip of virtual ip, has already been probed, so the host with real_ip has
        # already answered an arp request for it's mac address, and we surely learned from it
        outPort = self.macTable[dpid][ethPkt.dst]

        # old vIP mechanism
        self.oldVipToMac.setdefault(dstLanVip, {'mac':None, 'src':set()})
        self.oldVipToMac[dstLanVip]['mac'] = ethPkt.dst
        self.oldVipToMac[dstLanVip]['src'].add(srcLanRip)

        # InBound Translation rule
        match = parser.OFPMatch(
            eth_type=0x0800, 
            ipv4_dst=dstLanVip, 
            ipv4_src=srcLanRip, 
            eth_src=ethPkt.src
        )

        actions = [
            parser.OFPActionSetField(ipv4_dst=dstLanRip),
            parser.OFPActionSetField(ipv4_src=srcLanVip),
            parser.OFPActionOutput(outPort)
        ]

        self.addFlow(datapath, 10, match, actions, idleTimeout=10, notifyOnIdleExpiration=True)
        self._log('info', 'IP Tr.tion', f"Local InBound ({srcLanRip}:{dstLanVip}) to ({srcLanVip}:{dstLanRip})")

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=inPort,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)


    def installPublicInOutboundTranslation(self, datapath, inPort, pkt, ethPkt, ipPkt, msg) -> None:
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        dstPubVip = ipPkt.dst # eg. 143.255.10.250
        srcPubRip = ipPkt.src # eg. 87.23.3.42
        dstLanRip = self.pubToPriv[self.rips[dstPubVip]] # eg. 192.168.1.3

        outPort = self.macTable[dpid][ethPkt.dst]
        
        # old vIP mechanism
        self.oldVipToMac.setdefault(dstPubVip, {'mac':None, 'src':set()})
        self.oldVipToMac[dstPubVip]['mac'] = ethPkt.dst
        self.oldVipToMac[dstPubVip]['src'].add(srcPubRip)


        # InBound Translation rule (similar to the Local One)
        match_fwd = parser.OFPMatch(
            eth_type=0x0800, 
            ipv4_dst=dstPubVip, 
            ipv4_src=srcPubRip, 
            eth_src=ethPkt.src
        )
        actions_fwd = [
            parser.OFPActionSetField(ipv4_dst=dstLanRip),
            # we don't translate the real source IP into the virtual one. Because is coming from WAN,
            # and the destination MTD host must be able to answer back to that exact WAN ip
            parser.OFPActionOutput(outPort)
        ]
        self.addFlow(
            datapath, 
            10, 
            match_fwd, 
            actions_fwd, 
            idleTimeout=10, 
            notifyOnIdleExpiration=True
        )
        self._log('info', 'IP Tr.tion', f"Public InBound  ({srcPubRip}:{dstPubVip}) to ({srcPubRip}:{dstLanRip})")

        # OutBound Translation, the necessary exception for public virtual addresses connections.
        # Needed because when an MTD(s1) host reply to public, it must have it's virtual public address
        # as source ip, and not it's local one.
        match_rev = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=dstLanRip,
            ipv4_dst=srcPubRip,
            eth_src=ethPkt.dst  # The MTD host mac address
        )
        actions_rev = [
            parser.OFPActionSetField(ipv4_src=dstPubVip),
            # we don't translate the real destination ip into a real one, again because is public.
            parser.OFPActionOutput(inPort)
        ]
        self.addFlow(datapath, 10, match_rev, actions_rev, idleTimeout=10)
        self._log('info', 'IP Tr.tion', f"Public OutBound ({dstLanRip}:{srcPubRip}) <-> ({dstPubVip}:{srcPubRip})")
        # TOFIX: if the latter rule is installed, and, for example, the webserver pauses for more than 10 secs (so the latter rule expires) 
        # and then it sends out data, the packets will have ipSrc=webserver (real local ip) and ipDst=WAN, since the outbound translation on source IP
        # is not in place anymore, so WAN hosts (r2 in this case) will receive packets from a local ip, which is of course an issue.
        # It is easily fixed defining an openflow rule that matches the aforesaid conditions and simply drop the packet
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=inPort,
            actions=actions_fwd,
            data=msg.data
        )
        datapath.send_msg(out)

    def rewriteDnsAnswerForVirtualIp(self, datapath, pkt, ethPkt, ipPkt, dnsPkt) -> None:
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        udpPkt = pkt.get_protocol(udp.udp)
        
        for answer in dnsPkt.rr:
            if answer.rtype == QTYPE.A:
                realIp = str(answer.rdata)
                if realIp in self.vips:
                    virtIp = self.vips[realIp]
                    answer.rdata = A(virtIp)
                    answer.ttl = 0
                    self._log('info', 'DNS handler', f"Rewrote A-record {realIp} -> {virtIp} (TTL=0)")

        
        newDnsPayload = dnsPkt.pack()
        newPkt = packet.Packet()
        newPkt.add_protocol(ethernet.ethernet(
            dst=ethPkt.dst,
            src=ethPkt.src,
            ethertype=ethPkt.ethertype
        ))
        newPkt.add_protocol(ipv4.ipv4(
            dst=ipPkt.dst,
            src=ipPkt.src,
            proto=ipPkt.proto,
            ttl=ipPkt.ttl
        ))
        newPkt.add_protocol(udp.udp(
            dst_port=udpPkt.dst_port,
            src_port=udpPkt.src_port
        ))
        newPkt.add_protocol(newDnsPayload)
        newPkt.serialize()

        outPort = self.macTable.get(dpid, {}).get(ethPkt.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(outPort)]
        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=newPkt.data
            )
        )




    def handleNormalForwarding(self, datapath, inPort, ethPkt, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst = ethPkt.dst
        dpid = datapath.id

        outPort = self.macTable.get(dpid, {}).get(ethPkt.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(outPort)]

        if outPort != ofproto.OFPP_FLOOD:
            self.addFlow(
                datapath, 
                1, 
                parser.OFPMatch(in_port=inPort, eth_dst=dst), 
                actions
            )

        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=inPort,
                actions=actions,
                data=msg.data
            )
        )

    def _get_dns_protocol(self, pkt):
        ipPkt = pkt.get_protocol(ipv4.ipv4)
        udpPkt = pkt.get_protocol(udp.udp)
        if ipPkt and udpPkt and (udpPkt.src_port == 53 or udpPkt.dst_port == 53):
            if isinstance(pkt.protocols[-1], (bytes, bytearray)):
                try: return DNSRecord.parse(pkt.protocols[-1])
                except Exception: return None
        return None


    def _probeMAC(self, datapath, targetIp):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',
            src='00:00:00:00:00:00', # Sent from controller
            ethertype=0x0806
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac='00:00:00:00:00:00',
            src_ip='0.0.0.0', # Empty probe source IP
            dst_mac='00:00:00:00:00:00',
            dst_ip=targetIp
        ))
        pkt.serialize()

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
        self._log('info', 'ARP prober', f"Proactively searching MAC for Real Ip {targetIp}")

    def _learnMACTable(self, datapath, ethPkt, inPort):
        self.macTable.setdefault(datapath.id, {})
        if ethPkt.src not in self.macTable[datapath.id]:
            self._log('info', 'MAC Table', f"Learnt Switch({datapath.id}) <- InPort({inPort}) <- MAC({ethPkt.src})")
        self.macTable[datapath.id][ethPkt.src] = inPort

    def _learnARPTable(self, srcIp, srcMac):
        if srcIp not in self.arpTable:
            self._log('info', 'ARP Table', f"Learnt IP({srcIp}) -> MAC({srcMac})")
        self.arpTable[srcIp] = srcMac