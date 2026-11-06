# modules/blocklist.py
import threading
import time


class Blocklist:
    """Struttura dati condivisa: i bloccaggi possono arrivare sia dal detector sia
    da un admin esterno, e la whitelist protegge gli host da non bloccare mai.

    ttl (s): dopo quanto un blocco scade da solo (None = permanente). Il Mitigator
    installa la regola di drop con lo stesso hard_timeout, cosi' switch e blocklist
    restano allineati: se l'attacco continua, il detector lo rileva e lo riblocca."""

    def __init__(self, whitelist=None, ttl=None, clock=time.time):
        self._lock = threading.Lock()
        self._blocked = {}                       # mac -> {reason, source, ts, expires}
        self.whitelist = set(whitelist or set())
        self.ttl = ttl
        self._clock = clock                      # iniettabile nei test

    def _purge(self):
        now = self._clock()
        for mac in [m for m, e in self._blocked.items()
                    if e['expires'] is not None and e['expires'] <= now]:
            del self._blocked[mac]

    def block(self, mac, reason, source):
        with self._lock:
            if mac in self.whitelist:
                return False                     # host legittimo: mai bloccare
            self._purge()
            if mac in self._blocked:
                return False                     # gia' bloccato: niente da reinstallare
            now = self._clock()
            self._blocked[mac] = {'reason': reason, 'source': source, 'ts': now,
                                  'expires': now + self.ttl if self.ttl else None}
            return True

    def unblock(self, mac):
        with self._lock:
            self._blocked.pop(mac, None)

    def is_blocked(self, mac):
        with self._lock:
            self._purge()
            return mac in self._blocked

    def entries(self):
        with self._lock:
            self._purge()
            return dict(self._blocked)
