# experiments/detection_time.py — tempo di rilevamento/mitigazione e falsi positivi
#
# Incrocia il log eventi del controller (EVENT_LOG: ts,kind,mac,detector,bps,pps)
# con gli istanti di inizio flood scritti da scenario.py (<log>.flood_start[_a2]).
#
# Uso:  python3 experiments/detection_time.py <event_log> <flood_start_file> [...]
# Stampa una riga per MAC: primo DETECT e primo BLOCK in secondi dall'inizio flood
# (il flood piu' vicino, se ce ne sono piu' d'uno). I MAC legittimi che compaiono
# sono falsi positivi.
import sys

LEGIT = {'00:00:00:00:00:01': 'u1', '00:00:00:00:00:02': 'u2', '00:00:00:00:00:10': 'hsrv'}
ATTACKERS = {'00:00:00:00:00:f1': 'a1', '00:00:00:00:00:f2': 'a2'}


def load_events(path):
    events = []
    for line in open(path):
        parts = line.strip().split(',')
        if len(parts) >= 3:
            events.append((float(parts[0]), parts[1], parts[2]))
    return events


def summarize(events, t0):
    """{mac: {'DETECT': secondi, 'BLOCK': secondi}} relativi a t0 (primo evento)."""
    out = {}
    for ts, kind, mac in sorted(events):
        out.setdefault(mac, {}).setdefault(kind, ts - t0)
    return out


def main(event_log, flood_files):
    t0 = min(float(open(f).read().strip()) for f in flood_files)
    rows = summarize(load_events(event_log), t0)
    print('%-6s %-18s %-12s %-12s %s' % ('host', 'mac', 'detect [s]', 'block [s]', 'esito'))
    for mac, ev in sorted(rows.items()):
        name = ATTACKERS.get(mac) or LEGIT.get(mac, '?')
        esito = 'vero positivo' if mac in ATTACKERS else 'FALSO POSITIVO'
        fmt = lambda k: '%.1f' % ev[k] if k in ev else '-'  # noqa: E731
        print('%-6s %-18s %-12s %-12s %s' % (name, mac, fmt('DETECT'), fmt('BLOCK'), esito))
    for mac, name in ATTACKERS.items():
        if mac not in rows:
            print('%-6s %-18s %-12s %-12s %s' % (name, mac, '-', '-', 'non rilevato'))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("uso: python3 experiments/detection_time.py <event_log> <flood_start> [...]")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2:])
