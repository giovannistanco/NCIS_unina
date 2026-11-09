# modules/mitigator.py

# priorita' delle regole di drop: sopra il forwarding (1). Il Monitor la usa per
# escluderle dalle metriche (i loro contatori sono pacchetti scartati).
DROP_PRIORITY = 100


class Mitigator:
    """Installa/rimuove regole di DROP per il MAC sorgente malevolo (NON per porta,
    così un host legittimo sulla stessa porta non viene tagliato fuori).
    Rispetta la whitelist tramite la Blocklist."""

    def __init__(self, app, blocklist):
        self.app = app
        self.blocklist = blocklist

    def block_mac(self, src_mac, reason='dos'):
        """Ritorna True solo se il blocco e' nuovo (regole installate ora)."""
        if not self.blocklist.block(src_mac, reason=reason, source='detector'):
            return False  # whitelisted o già bloccato
        for dp in list(self.app.datapaths.values()):
            self._drop_flow(dp, src_mac, add=True)
        self.app.logger.warning("BLOCK %s (%s)", src_mac, reason)
        return True

    def unblock_mac(self, src_mac):
        self.blocklist.unblock(src_mac)
        for dp in list(self.app.datapaths.values()):
            self._drop_flow(dp, src_mac, add=False)
        self.app.logger.info("UNBLOCK %s", src_mac)

    def _drop_flow(self, dp, src_mac, add):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(eth_src=src_mac)
        if add:
            # hard_timeout = ttl della blocklist (0 = permanente): lo sblocco e' dello switch
            mod = parser.OFPFlowMod(datapath=dp, priority=DROP_PRIORITY, match=match,
                                    instructions=[],   # nessuna azione = drop
                                    hard_timeout=int(self.blocklist.ttl or 0),
                                    command=ofp.OFPFC_ADD)
        else:
            mod = parser.OFPFlowMod(datapath=dp, priority=DROP_PRIORITY, match=match,
                                    command=ofp.OFPFC_DELETE,
                                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
        dp.send_msg(mod)
