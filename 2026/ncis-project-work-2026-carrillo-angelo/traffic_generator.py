#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traffic_generator.py
=====================
Script da eseguire su tutti gli host Mininet: server, utenti
legittimi e bot. Il comportamento è selezionato sfruttando l'argomento
--role, nel seguente modo:

    --role server   h1: si mette in ascolto su HTTP_PORT e accetta le
                    connessioni. In pratica serve solo a far completare il TCP
                    handshake affinché il payload GET arrivi effettivamente
                    sulla rete e sia ispezionabile dal controller.

    --role user     h2/h3/h4: prende i percorsi HTTP da un catalogo
                    con 100 path generati proceduralmente. Ciò garantisce
                    un'alta probabilità che le richieste, in una finestra di
                    pochi secondi, risultino quasi tutte diverse tra
                    loro, ottenendo un MIR alto.

    --role bot      h5/h6: prende i percorsi da un "Emulation Dictionary"
                    di soli 3 percorsi fissi. Impiega quindi lo stesso protocollo
                    e timing degli utenti legittimi, ma con un contenuto
                    applicativo altamente ripetitivo, dando un MIR basso.
                    Questa proprietà lo rende rilevabile da un'analisi semantica,
                    mentre è invisibile a un controllo volumetrico.

Esempi:
    h1  python3 traffic_generator.py --role server
    h2  python3 traffic_generator.py --role user --target 10.0.0.1
    h5  python3 traffic_generator.py --role bot  --target 10.0.0.1
"""

import argparse
import random
import socket
import string
import threading
import time


# ---------------------------------------------------------------------------
# Catalogo per gli Utenti Legittimi: 100 percorsi generati a runtime,
# combinando categorie + id numerico + suffisso in modo randomico.
# Campionamento con reinserimento, ma pool ampio per arrivare a un MIR locale alto.
# ---------------------------------------------------------------------------
def _build_legit_catalog(n=100):
    categories = ['products', 'articles', 'users', 'search', 'api',
                  'images', 'videos', 'blog', 'docs', 'support']
    catalog = set()
    while len(catalog) < n:
        cat = random.choice(categories)
        rid = random.randint(1000, 99999)
        suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
        catalog.add(f"/{cat}/{rid}/{suffix}")
    return list(catalog)


LEGIT_URL_CATALOG = _build_legit_catalog(100)

# ---------------------------------------------------------------------------
# "Emulation Dictionary" del Bot: solo 3 percorsi fissi, scelti per sembrare
# traffico applicativo possibile e non rumore casuale.
# ---------------------------------------------------------------------------
BOT_URL_DICTIONARY = [
    "/index.html",
    "/api/v1/ping",
    "/wp-login.php",
]


def make_http_get(path, host_ip):
    """Costruisce una richiesta HTTP GET testuale minimale."""
    return (f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_ip}\r\n"
            f"User-Agent: MininetTrafficGen/1.0\r\n"
            f"Connection: close\r\n\r\n")


def run_server(args):
    """
    Ruolo SERVER (h1): in ascolto su args.port, accetta le connessioni
    TCP in arrivo, legge e scarta la richiesta, chiude. Non è un vero
    web server, dato che lo scopo è quello di far completare l'handshake TCP
    così che il payload GET venga effettivamente trasmesso e possa essere
    poi ispezionato dal controller Ryu sullo switch Edge del server.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', args.port))
    srv.listen(64)
    print(f"[SERVER] In ascolto su 0.0.0.0:{args.port} ...")

    def handle(conn, addr):
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if data:
                first_line = data.decode('utf-8', errors='ignore').split('\r\n')[0]
                print(f"[SERVER] Richiesta da {addr[0]}: {first_line}")
        except Exception:
            pass
        finally:
            conn.close()

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


def run_client(args, url_pool, label):
    """
    Ruolo CLIENT generico usato sia da --role user sia da --role bot,
    ma con pool di URL differente. Invia richieste HTTP GET verso il
    target per args.duration secondi, con intervalli casuali tra una
    richiesta e l'altra per simulare un comportamento umano e genuino.
    """
    start = time.time()
    sent = 0
    try:
        while time.time() - start < args.duration:
            path = random.choice(url_pool)
            request = make_http_get(path, args.target)

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((args.target, args.port))
                s.sendall(request.encode('utf-8'))
                s.close()
                sent += 1
                print(f"[{label}] #{sent} GET {path} -> {args.target}:{args.port}")
            except Exception as exc:
                # Punto in cui tipicamente avviene il blocco applicato
                # dal controller (connection refused / timeout) una volta
                # che l'host viene classificato come botnet.
                print(f"[{label}] richiesta fallita ({exc}) -- possibile blocco firewall in corso")

            time.sleep(random.uniform(args.min_interval, args.max_interval))
    except KeyboardInterrupt:
        pass


def main():
    parser = argparse.ArgumentParser(description="Generatore di traffico HTTP per il lab SDN Security")
    parser.add_argument('--role', required=True, choices=['server', 'user', 'bot'],
                         help="Ruolo dell'host: server (target), user (legittimo) o bot")
    parser.add_argument('--target', default='10.0.0.1',
                         help="IP del server target (per --role user/bot)")
    parser.add_argument('--port', type=int, default=80,
                         help="Porta TCP applicativa (default 80)")
    parser.add_argument('--duration', type=float, default=300.0,
                         help="Durata invio traffico in secondi (per user/bot)")
    parser.add_argument('--min-interval', type=float, default=0.4,
                         help="Intervallo minimo (s) tra due richieste consecutive")
    parser.add_argument('--max-interval', type=float, default=1.5,
                         help="Intervallo massimo (s) tra due richieste consecutive")
    args = parser.parse_args()

    if args.role == 'server':
        run_server(args)
    elif args.role == 'user':
        run_client(args, LEGIT_URL_CATALOG, label='USER')
    elif args.role == 'bot':
        run_client(args, BOT_URL_DICTIONARY, label='BOT ')


if __name__ == '__main__':
    main()
