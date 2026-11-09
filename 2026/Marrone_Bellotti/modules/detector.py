# modules/detector.py
from collections import deque

import joblib

# byte/s: sotto questa soglia un flusso e' considerato inattivo (rate ~0, es. i flussi
# di forwarding di un host gia' bloccato che restano in tabella; le regole di drop non
# arrivano qui, le scarta il Monitor). Lo stesso filtro e' applicato in
# ml/extract_features.py al dataset di training: il modello non vede mai questi
# campioni, quindi non deve neppure classificarli a runtime.
ACTIVE_FLOOR = 50000


class Detector:
    """Interfaccia: classify(source_id, **features) -> 'benign'|'attack'.

    Il controller chiama classify una volta per intervallo e per SORGENTE (MAC), con
    le feature aggregate di modules/features.py: pps, bps, pkt_size, dpps, dur."""

    def classify(self, flow_id, **features):
        raise NotImplementedError


class AdaptiveThresholdDetector(Detector):
    """Soglia adattiva EWMA per sorgente, su bps E su pps, piu' un tetto assoluto.

    Una sorgente è 'attacco' se:
      (a) supera un TETTO DURO (`hard_bps` o `hard_pps`) — vale anche durante il
          warm-up e copre il cold start: un flood che parte gia' al massimo
          diventerebbe la baseline e la sola EWMA non lo segnalerebbe mai; oppure
      (b) per almeno una metrica è ANOMALA rispetto alla propria baseline
          (> media + k·std e > 2·media) E supera la soglia minima (`min_bps`,
          `min_pps`). La deviazione standard usata è almeno `min_rel_std`·media, così
          un flusso quasi costante non scatta per un piccolo aumento. Come per il
          tetto, l'anomalia sui byte/s conta solo se la sorgente non riceve risposte;
          quella sui pps conta sempre.

    L'EWMA è aggiornata sempre (con damping quando il campione è anomalo): così la
    baseline non si congela al primo picco, evitando cascate di falsi positivi su
    traffico legittimo bursty (es. TCP).

    hard_bps=None / hard_pps=None disattivano il tetto (comportamento "solo EWMA").
    Default: link da 10 Mbps = 1.25 MB/s; tetto a ~76% (0.95 MB/s): un flood a freddo
    sul link d'accesso entra a 1.04-1.35 MB/s (misurato). Il TCP legittimo e' esentato
    dalle risposte; un UDP legittimo sopra il tetto no (limite). Senza `rx_pps`
    (dataset offline, che non ha eth_dst) il tetto sui byte/s scatta come prima.

    Isteresi sul tetto dei byte/s: una sorgente che l'ha superato senza risposte resta
    sopra il tetto finche' non scende sotto `hard_bps_release` (o riceve risposte). Un
    flood che per un intervallo rallenta sotto il tetto non fa ripartire la conferma.

    Chi risponde non e' un attaccante: una sorgente che riceve piu' di `responder_min`
    volte quello che manda (es. il server sotto un SYN flood: riceve SYN + RST, manda
    SYN-ACK) non viene mai segnalata, nemmeno dal tetto sui pps. Senza whitelist il
    server veniva bloccato e il DoS lo completava il controller.
    """

    def __init__(self, k=3.0, alpha=0.3, warmup=3, min_bps=150000, min_pps=500,
                 hard_bps=0.95e6, hard_pps=2000, min_rel_std=0.1, reply_max=0.1,
                 hard_bps_release=0.6e6, responder_min=1.2):
        self.k, self.alpha, self.warmup = k, alpha, warmup
        self.floors = {'bps': min_bps, 'pps': min_pps}
        self.hard = {'bps': hard_bps, 'pps': hard_pps}
        self.min_rel_std = min_rel_std
        self.reply_max = reply_max
        self.hard_bps_release = hard_bps_release
        self.responder_min = responder_min
        self.over_bps = set()  # sorgenti che hanno superato il tetto sui byte/s
        self.mean, self.var, self.n = {}, {}, {}

    def _is_anom(self, key, x, n):
        mean = self.mean.get(key, x)
        std = max(self.var.get(key, 0.0) ** 0.5, self.min_rel_std * mean)
        return (n >= self.warmup and x > self.floors[key[1]]
                and x > mean + self.k * std and x > mean * 2)

    def _update(self, key, x, anom):
        mean = self.mean.get(key, x)
        var = self.var.get(key, 0.0)
        # EWMA sempre aggiornata; damping (alpha ridotto) se anomala -> non "impara"
        # l'attacco troppo in fretta ma non si congela.
        a = self.alpha * (0.2 if anom else 1.0)
        new_mean = (1 - a) * mean + a * x
        self.var[key] = (1 - a) * var + a * (x - new_mean) ** 2
        self.mean[key] = new_mean

    def classify(self, flow_id, bps=0.0, pps=0.0, rx_pps=None, **_):
        n = self.n.get(flow_id, 0)
        values = {'bps': bps, 'pps': pps}
        no_reply = rx_pps is None or rx_pps < self.reply_max * pps
        limit = self.hard['bps']
        if limit is not None and flow_id in self.over_bps:
            limit = self.hard_bps_release
        over_bps = limit is not None and bps > limit and no_reply
        if over_bps:
            self.over_bps.add(flow_id)
        else:
            self.over_bps.discard(flow_id)
        over_hard = over_bps or (self.hard['pps'] is not None and pps > self.hard['pps'])
        anom = {m: self._is_anom((flow_id, m), x, n) for m, x in values.items()}
        # stessa regola del tetto: un picco di byte/s con risposte e' un TCP che
        # accelera (es. u1 che si riprende dopo il blocco dell'attaccante), non un flood
        anom['bps'] = anom['bps'] and no_reply
        responder = rx_pps is not None and rx_pps > self.responder_min * pps
        is_anom = (over_hard or any(anom.values())) and not responder
        for m, x in values.items():
            self._update((flow_id, m), x, is_anom)
        self.n[flow_id] = n + 1
        return 'attack' if is_anom else 'benign'


class MLDetector(Detector):
    """Carica un modello sklearn e classifica le sorgenti. Non ha bisogno di storia:
    copre il cold start, ma generalizza solo agli attacchi simili a quelli visti in
    training.

    `threshold`: probabilita' di attacco minima per dire 'attack' (0.5 = predict).
    Alzarla riduce i falsi positivi sugli host onesti al prezzo di attaccanti persi."""

    def __init__(self, model_path, threshold=0.5):
        bundle = joblib.load(model_path)
        self.model = bundle['model']
        self.features = bundle['features']
        self.active_floor = bundle.get('active_floor', ACTIVE_FLOOR)
        self.threshold = threshold

    def classify(self, flow_id, **features):
        # flussi inattivi: fuori dalla distribuzione di training -> benigni per costruzione
        if features.get('bps', 0.0) <= self.active_floor:
            return 'benign'
        row = [[features.get(f, 0.0) for f in self.features]]
        p_attack = self.model.predict_proba(row)[0][1]
        return 'attack' if p_attack >= self.threshold else 'benign'


class EnsembleDetector(Detector):
    """OR di piu' detector (es. ML per il cold start + EWMA per attacchi nuovi).
    Tutti vengono chiamati a ogni intervallo, cosi' ciascuno aggiorna il proprio stato."""

    def __init__(self, detectors):
        self.detectors = detectors

    def classify(self, flow_id, **features):
        verdicts = [d.classify(flow_id, **features) for d in self.detectors]
        return 'attack' if 'attack' in verdicts else 'benign'


class Confirmer:
    """Isteresi: conferma un attacco solo se almeno `k` degli ultimi `n` intervalli
    della sorgente sono 'attack'. Riduce i falsi positivi su picchi isolati, al costo
    di un intervallo di ritardo (5 s)."""

    def __init__(self, k=2, n=3):
        self.k, self.n = k, n
        self.history = {}

    def update(self, src, verdict):
        h = self.history.setdefault(src, deque(maxlen=self.n))
        h.append(verdict == 'attack')
        return sum(h) >= self.k


def top_talker(per_src, exclude=()):
    """Sorgente con piu' banda nell'intervallo, esclusi i MAC in `exclude` e i flussi
    inattivi. Usato dal rilevamento per congestione: quando un link e' saturo si
    blocca chi lo sta occupando, senza guardare la storia del flusso."""
    cands = {s: m['bps'] for s, m in per_src.items()
             if s not in exclude and m['bps'] > ACTIVE_FLOOR}
    return max(cands, key=cands.get) if cands else None
