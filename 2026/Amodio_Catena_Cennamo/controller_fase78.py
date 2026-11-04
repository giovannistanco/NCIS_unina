# -*- coding: utf-8 -*-
"""
controller_mitigation.py - Fasi 5, 6, 7 e 8 con Quarantena e Redirection

- Tabella 0:
    * Priorità 200: QUARANTENA / DROP mirato sull'IP sorgente (Fase 7) con timeout di sblocco (Fase 8)
                    Se ENABLE_QUARANTINE=True: riscrittura L2/L3 e reindirizzamento su h6 per ispezione
                    Se ENABLE_QUARANTINE=False: scarto pacchetti (drop standard)
    * Priorità 100: Metering corsia TCP per ciascuna porta di accesso
    * Priorità 50:  Metering corsia NON-TCP per ciascuna porta di accesso
    * Priorità 0:   Default goto_table 1
- Tabella 1: Forwarding L2 ordinario (simple_switch_13)

Modifiche:
    1. Aggiunta configurazione Quarantena (h6 su porta 4 di s1)
    2. Modificata _apply_drop_rule() per supportare la Redirection con SetField ed Output verso h6
    3. Aggiornati i log di allarme, sblocco e stato CSV indicando la quarantena
"""

import csv
import time

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

# Parametri di Monitoraggio
INTERVAL = 2

# Soglie Allarme
THRESHOLD_NON_TCP = 200000   # 1.6 Mbit/s in byte/s
CONSECUTIVE_NON_TCP = 3      # ~6 secondi

THRESHOLD_TCP = 625000       # 5.0 Mbit/s in byte/s
CONSECUTIVE_TCP = 10         # ~20 secondi

# Durata del blocco/quarantena in secondi (Fase 8)
BLOCK_HARD_TIMEOUT = 15

# Riblocco rapido dei recidivi dopo lo sblocco
FAST_REBLOCK = True

# ==============================================================================
# CONFIGURAZIONE QUARANTENA & ISPEZIONE (Nuova Funzionalità)
# ==============================================================================
ENABLE_QUARANTINE = True        # True: Reindirizza su h6 | False: Drop puro
QUARANTINE_HOST = 'h6'
QUARANTINE_IP = '10.0.0.6'
QUARANTINE_MAC = '00:00:00:00:00:06'
QUARANTINE_DPID = 1            # Switch S1 (a cui è collegato h1)
QUARANTINE_PORT = 4           # Porta fisica di S1 a cui è collegato h6
# ==============================================================================

# Mappatura Porte di Accesso: (dpid, porta) -> host
ACCESS_PORTS = {
    (1, 1): 'h1',
    (1, 2): 'h4',
    (2, 1): 'h2',
    (2, 2): 'h5',
    (4, 1): 'h3',
}

# Indirizzi IP per mitigazione mirata
HOST_IPS = {
    'h1': '10.0.0.1',
    'h2': '10.0.0.2',
    'h3': '10.0.0.3',
    'h4': '10.0.0.4',
    'h5': '10.0.0.5',
    'h6': '10.0.0.6',
}

WHITELIST = {'h3', 'h5', 'h6'}
CSV_FILE = 'monitor_mitigation.csv'

NORMALE = 'NORMALE'
ALLARME = 'ALLARME'
BLOCCATO = 'BLOCCATO'

COOKIE_NON_TCP = 0x10
COOKIE_TCP     = 0x20
COOKIE_DROP    = 0x99


class DualLaneMitigationSwitch(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(DualLaneMitigationSwitch, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.prev_flow = {}
        self.counter = {}
        self.state = {}
        self.active_blocks = set()
        self.first_after_unblock = set()

        self.t0 = time.time()
        self.csv_file = open(CSV_FILE, 'w', newline='')
        self.csv = csv.writer(self.csv_file)
        self.csv.writerow([
            't_s', 'dpid', 'port', 'host', 'lane',
            'rx_Bps', 'rx_Mbps', 'counter', 'state', 'nota'
        ])
        self.csv_file.flush()

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info('Switch collegato: s%s', dp.id)
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.info('Switch scollegato: s%s', dp.id)
                del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst_goto_t1 = [parser.OFPInstructionGotoTable(table_id=1)]

        # Tabella 0: Regole di Misura per tutte le porte di accesso
        for (dpid, port), host in ACCESS_PORTS.items():
            if dpid == datapath.id:
                # Regola TCP (priorità 100)
                match_tcp = parser.OFPMatch(
                    in_port=port,
                    eth_type=0x0800,
                    ip_proto=6
                )
                self._add_flow_raw(datapath, table_id=0, priority=100,
                                   match=match_tcp, instructions=inst_goto_t1,
                                   cookie=COOKIE_TCP)

                # Regola NON-TCP (priorità 50)
                match_nontcp = parser.OFPMatch(in_port=port)
                self._add_flow_raw(datapath, table_id=0, priority=50,
                                   match=match_nontcp, instructions=inst_goto_t1,
                                   cookie=COOKIE_NON_TCP)

        # Tabella 0 (priorità 0): default a Tabella 1
        self._add_flow_raw(datapath, table_id=0, priority=0,
                           match=parser.OFPMatch(), instructions=inst_goto_t1)

        # Tabella 1 (priorità 0): Table-miss verso il controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst_t1 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._add_flow_raw(datapath, table_id=1, priority=0,
                           match=parser.OFPMatch(), instructions=inst_t1)

    def _add_flow_raw(self, datapath, table_id, priority, match, instructions,
                       cookie=0, hard_timeout=0, idle_timeout=0):
        parser = datapath.ofproto_parser
        flags = datapath.ofproto.OFPFF_SEND_FLOW_REM if hard_timeout > 0 else 0
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
            flags=flags
        )
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=1,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(INTERVAL)

    def _request_flow_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(
            dp, table_id=0,
            out_port=dp.ofproto.OFPP_ANY,
            out_group=dp.ofproto.OFPG_ANY
        )
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        t = time.time() - self.t0
        records = []

        for stat in sorted(ev.msg.body, key=lambda s: (s.match.get('in_port', 0), s.priority)):
            in_port = stat.match.get('in_port')
            if not in_port or (dpid, in_port) not in ACCESS_PORTS:
                continue

            if stat.cookie == COOKIE_TCP:
                lane = 'TCP'
            elif stat.cookie == COOKIE_NON_TCP:
                lane = 'NON-TCP'
            else:
                continue

            host = ACCESS_PORTS[(dpid, in_port)]
            key = (dpid, in_port, lane)

            t_sw = stat.duration_sec + (stat.duration_nsec / 1e9)
            prev = self.prev_flow.get(key)
            self.prev_flow[key] = (stat.byte_count, t_sw)

            if prev is None:
                continue

            dt = t_sw - prev[1]
            if dt <= 0:
                continue

            rx_bps = (stat.byte_count - prev[0]) / dt
            counter, state, nota = self._evaluate_and_mitigate(ev.msg.datapath, key, host, lane, rx_bps)

            records.append((in_port, host, lane, rx_bps, counter, state, nota))
            self.csv.writerow([
                round(t, 2), dpid, in_port, host, lane,
                round(rx_bps), round((rx_bps * 8) / 1e6, 3),
                counter, state, nota
            ])

        self.csv_file.flush()
        if records:
            self._print_table(dpid, t, records)

    def _evaluate_and_mitigate(self, datapath, key, host, lane, rx_bps):
        dpid, in_port, _ = key
        counter = self.counter.get(key, 0)
        state = self.state.get(key, NORMALE)
        nota = ''

        # Stato BLOCCATO / IN QUARANTENA
        if (dpid, host, lane) in self.active_blocks:
            self.counter[key] = 0
            self.state[key] = BLOCCATO
            azione_desc = f'quarantena attiva -> {QUARANTINE_HOST}' if ENABLE_QUARANTINE else 'blocco attivo (drop)'
            return 0, BLOCCATO, azione_desc

        if state == BLOCCATO:
            state = NORMALE
            nota = 'blocco/quarantena scaduta'

        partial = key in self.first_after_unblock
        self.first_after_unblock.discard(key)

        threshold = THRESHOLD_TCP if lane == 'TCP' else THRESHOLD_NON_TCP
        max_consecutive = CONSECUTIVE_TCP if lane == 'TCP' else CONSECUTIVE_NON_TCP

        if rx_bps > threshold:
            if host in WHITELIST:
                counter = 0
                nota = 'in whitelist (esente)'
                self.logger.info('S%d porta %d (%s): sopra soglia ma in WHITELIST. Nessun allarme.',
                                 dpid, in_port, host)
            elif state == ALLARME:
                nota = 'allarme persistente'
            else:
                counter += 1
                nota = f'sforamento {counter}/{max_consecutive}'
                if counter >= max_consecutive:
                    state = ALLARME
                    azione_label = 'QUARANTENA' if ENABLE_QUARANTINE else 'DROP'
                    nota = f'ALLARME ({lane}) -> {azione_label} ATTIVATO'
                    self.logger.warning(
                        '*** S%d porta %d (%s) ALLARME %s! Applicazione %s ***',
                        dpid, in_port, host, lane, azione_label
                    )
                    self._apply_drop_rule(datapath, host, lane)
        else:
            if partial:
                nota = 'primo intervallo dopo lo sblocco (parziale): in osservazione'
            else:
                if counter > 0 or state == ALLARME:
                    nota = 'rientro nei limiti'
                counter = 0
                state = NORMALE

        self.counter[key] = counter
        self.state[key] = state
        return counter, state, nota

    def _apply_drop_rule(self, datapath, host, lane):
        dpid = datapath.id
        block_id = (dpid, host, lane)

        if block_id in self.active_blocks:
            return
        self.active_blocks.add(block_id)

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        src_ip = HOST_IPS.get(host)

        # Match selettivo per protocollo L4
        if lane == 'NON-TCP':
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
                ip_proto=17
            )
        else:
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
                ip_proto=6
            )

        # Selezione Azione: Quarantena (Redirection) oppure DROP puro
        if ENABLE_QUARANTINE and dpid == QUARANTINE_DPID:
            # Reindirizza il flusso su h6:
            # 1. Riscrive il MAC di destinazione con quello di h6
            # 2. Riscrive l'IP di destinazione con quello di h6
            # 3. Invia fuori dalla porta fisica a cui è collegato h6
            actions = [
                parser.OFPActionSetField(eth_dst=QUARANTINE_MAC),
                parser.OFPActionSetField(ipv4_dst=QUARANTINE_IP),
                parser.OFPActionOutput(QUARANTINE_PORT)
            ]
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            desc_log = f"QUARANTENA (Dirottato su {QUARANTINE_HOST}:{QUARANTINE_PORT})"
        else:
            # DROP tradizionale: lista azioni vuota
            instructions = []
            desc_log = "DROP (Scarto pacchetti)"

        self._add_flow_raw(
            datapath=datapath,
            table_id=0,
            priority=200,
            match=match,
            instructions=instructions,
            cookie=COOKIE_DROP,
            hard_timeout=BLOCK_HARD_TIMEOUT
        )
        self.logger.warning(
            '>>> REGOLA DI MITIGAZIONE INSTALLATA: S%d applica %s a %s (IP: %s) per %ds <<<',
            dpid, desc_log, host, src_ip, BLOCK_HARD_TIMEOUT
        )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if msg.cookie == COOKIE_DROP:
            src_ip = msg.match.get('ipv4_src', 'sconosciuto')
            host_name = next((h for h, ip in HOST_IPS.items() if ip == src_ip), src_ip)
            azione_label = "QUARANTENA" if ENABLE_QUARANTINE else "DROP"
            self.logger.info(
                '<<< SBLOCCO: Regola di %s scaduta su S%d per %s (IP: %s). Ripristino forwarding normale verso destinazione originale. >>>',
                azione_label, dp.id, host_name, src_ip
            )
            self.active_blocks = {b for b in self.active_blocks if not (b[0] == dp.id and b[1] == host_name)}

            if FAST_REBLOCK:
                lane = 'TCP' if msg.match.get('ip_proto') == 6 else 'NON-TCP'
                max_consecutive = CONSECUTIVE_TCP if lane == 'TCP' else CONSECUTIVE_NON_TCP
                for (d, p), h in ACCESS_PORTS.items():
                    if d == dp.id and h == host_name:
                        self.counter[(d, p, lane)] = max_consecutive - 1
                        self.state[(d, p, lane)] = NORMALE
                        self.first_after_unblock.add((d, p, lane))
                        self.logger.info(
                            '%s sotto osservazione su S%d: al prossimo sforamento verra\' riapplicata la mitigazione.',
                            host_name, dp.id
                        )

    def _print_table(self, dpid, t, records):
        print(f"\n--- s{dpid} | t={t:.1f}s ---")
        print(f"{'porta':<6} {'host':<5} {'corsia':<8} {'rx_B/s':>12} {'rx_Mbps':>10} {'cont':>5} {'stato':<8} {'nota'}")
        for p, h, lane, rx, cnt, st, nota in records:
            print(f"{p:<6} {h:<5} {lane:<8} {rx:>12.0f} {(rx * 8 / 1e6):>10.2f} {cnt:>5} {st:<8} {nota}")