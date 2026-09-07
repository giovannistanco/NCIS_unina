#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
topology.py
=====================================================
Topologia Mininet ad albero (Core / Aggregation / Edge) per il project
work sulla traccia di SDN Security, con cattura automatica del traffico HTTP sul
Server Target (h1) tramite tshark.

Struttura topologica:
    - 1 switch Core    : s1
    - 2 switch Aggreg. : s2, s3
    - 4 switch Edge    : s4, s5, s6, s7
    - 6 host           : h1...h6

Ruoli host:
    h1  10.0.0.1   SERVER TARGET        -> Edge s4 (dpid 4)
    h2  10.0.0.2   Utente legittimo     -> Edge s4 (dpid 4)
    h3  10.0.0.3   Utente legittimo     -> Edge s5 (dpid 5)
    h4  10.0.0.4   Utente legittimo     -> Edge s6 (dpid 6)
    h5  10.0.0.5   Bot                  -> Edge s6 (dpid 6)
    h6  10.0.0.6   Bot                  -> Edge s7 (dpid 7)

Logica di packet capture:
    - Si avvia dopo net.start(): a quel punto h1-eth0 esiste già nel
      namespace di rete di h1 e tshark può aprirla.
    - Il processo gira nel namespace di h1 tramite h1.popen(). In particolare, h1.popen() usa
      internamente mnexec per isolare il processo nel network
      namespace corretto: h1-eth0 è l'unica interfaccia visibile.
    - Il filtro BPF 'tcp port 80' limita la cattura al solo traffico
      HTTP, eliminando ARP, ICMP, handshake OpenFlow e tutto il resto.
    - Il blocco try/finally è necessario a garantire la terminazione del processo di
      cattura anche in caso di Ctrl+C, così da evitareprocessi zombie e
      file pcap troncati/non finalizzati.
    - Il file server_capture.pcap viene rimosso a ogni avvio al fine di
      non concatenare dati di sessioni di test diverse.

Analisi post-test:
    wireshark server_capture.pcap
    tshark -r server_capture.pcap -T fields -e frame.number \
           -e ip.src -e http.request.uri
"""

import os
import pwd
import shutil
import subprocess

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


# ---------------------------------------------------------------------------
# Configurazione controller
# ---------------------------------------------------------------------------
CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6653

# ---------------------------------------------------------------------------
# [PACKET CAPTURE] Parametri di cattura
# ---------------------------------------------------------------------------

# Interfaccia su cui fare sniffing. In Mininet, h1.popen() gira nel namespace
# di rete di h1: da lì l'interfaccia si chiama h1-eth0
CAPTURE_IFACE = 'h1-eth0'

# Filtro BPF che esclude ARP, ICMP ping, traffico OpenFlow
# e qualsiasi altro protocollo non pertinente all'analisi.
BPF_FILTER = 'tcp port 80'

# Percorso del file di output. Esso è relativo alla CWD da cui si lancia
# il comando `sudo python3 topology.py`, ovvero la directory del progetto.
PCAP_OUTPUT = '/tmp/server_capture.pcap'

# Timeout in secondi per la terminazione ordinata del processo di cattura
# dopo SIGTERM, prima di ricorrere a SIGKILL.
CAPTURE_TERM_TIMEOUT = 10


def _resolve_capture_command():
    """
    Determina il comando di cattura da usare.

    Prima scelta: tshark grazie all´output più ricco, direttamente analizzabile con
    le API di Wireshark e al supporto di -q per sopprimere il contatore
    progressivo.

    Ripiego: tcpdump per la presenza quasi globale senza necessità di installazioni aggiuntive.

    Ritorna la lista di token del comando, o None se nessuno dei due tool è installato.

    Note sui flag:
        tshark
          -i  interfaccia di cattura
          -f  filtro BPF (applicato a livello kernel, prima della copia
              in user-space per ridurre overhead)
          -w  file di output pcap/pcapng
          -q  sopprime il contatore "N packets captured" su stderr
              (tiene il prompt della CLI di Mininet pulito)

        tcpdump
          -i  interfaccia di cattura
          -w  file di output pcap
          -U  packet-buffered: viene eseguito il flush di ogni pacchetto su disco
              immediatamente senza la necessità aspettare il riempimento del
              buffer interno. Critico con Ctrl+C dato che, senza -U, l'ultimo
              chunk di pacchetti in buffer verrebbe perso.
          Il filtro BPF va come argomento posizionale finale (senza flag)
    """
    if shutil.which('tshark'):
        return [
            'tshark',
            '-i', CAPTURE_IFACE,
            '-f', BPF_FILTER,
            '-w', PCAP_OUTPUT,
            '-q',
        ]
    if shutil.which('tcpdump'):
        return [
            'tcpdump',
            '-i', CAPTURE_IFACE,
            '-w', PCAP_OUTPUT,
            '-U',
            BPF_FILTER,
        ]
    return None


def build_topology():

    # -----------------------------------------------------------------------
    # [PACKET CAPTURE — Passo 0] Pulizia preventiva del file pcap
    # -----------------------------------------------------------------------
    # Rimosso prima di costruire la rete (e quindi prima di avviare la
    # cattura). L'approccio try/except rispetto alla sinergia di
    # os.path.exists() + os.remove() separati evita la race condition
    # Time-of-Check to Time-of-UseOCTOU tra il check e la rimozione, che potrebbe verificarsi
    # nel caso un processo cancelli un file che è stato appena controllato e non rimosso dal programma
    try:
        os.remove(PCAP_OUTPUT)
        info(f'*** [CAPTURE] File precedente rimosso: {PCAP_OUTPUT}\n')
    except FileNotFoundError:
        pass    # prima esecuzione o percorso già pulito: nessuna azione

    # -----------------------------------------------------------------------
    # Costruzione della topologia
    # -----------------------------------------------------------------------
    net = Mininet(controller=None, switch=OVSKernelSwitch,
                   autoSetMacs=True, build=False)

    info('*** Aggiunta controller remoto (Ryu)\n')
    c0 = net.addController('c0', controller=RemoteController,
                            ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    info('*** Creazione switch OpenFlow 1.3\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13')  # Core
    s2 = net.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13')  # Aggregation 1
    s3 = net.addSwitch('s3', dpid='0000000000000003', protocols='OpenFlow13')  # Aggregation 2
    s4 = net.addSwitch('s4', dpid='0000000000000004', protocols='OpenFlow13')  # Edge 1
    s5 = net.addSwitch('s5', dpid='0000000000000005', protocols='OpenFlow13')  # Edge 2
    s6 = net.addSwitch('s6', dpid='0000000000000006', protocols='OpenFlow13')  # Edge 3
    s7 = net.addSwitch('s7', dpid='0000000000000007', protocols='OpenFlow13')  # Edge 4

    info('*** Cablaggio dorsale ad albero (Core -> Aggregation -> Edge)\n')
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s2, s4)
    net.addLink(s2, s5)
    net.addLink(s3, s6)
    net.addLink(s3, s7)

    info('*** Creazione host\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')  # Server Target
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')  # Utente legittimo
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # Utente legittimo
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')  # Utente legittimo
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')  # Bot 1
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')  # Bot 2

    info('*** Collegamento host -> switch Edge\n')
    net.addLink(h1, s4)
    net.addLink(h2, s4)
    net.addLink(h3, s5)
    net.addLink(h4, s6)
    net.addLink(h5, s6)
    net.addLink(h6, s7)

    info('*** Costruzione e avvio rete\n')
    net.build()
    net.start()

    info('\n*** Topologia attiva. Riepilogo ruoli:\n')
    info('    h1 10.0.0.1  SERVER TARGET    (Edge s4 / dpid 4)\n')
    info('    h2 10.0.0.2  Utente legittimo (Edge s4 / dpid 4)\n')
    info('    h3 10.0.0.3  Utente legittimo (Edge s5 / dpid 5)\n')
    info('    h4 10.0.0.4  Utente legittimo (Edge s6 / dpid 6)\n')
    info('    h5 10.0.0.5  BOT 1            (Edge s6 / dpid 6)\n')
    info('    h6 10.0.0.6  BOT 2            (Edge s7 / dpid 7)\n\n')

    # -----------------------------------------------------------------------
    # [PACKET CAPTURE — Passo 1] Risoluzione del comando di cattura
    # -----------------------------------------------------------------------
    capture_cmd = _resolve_capture_command()
    capture_proc = None

    if capture_cmd is None:
        # Degradazione controllata: la topologia funziona comunque,
        # solo la cattura pcap è disabilitata.
        info('*** [CAPTURE] ATTENZIONE: tshark e tcpdump non trovati nel PATH.\n')
        info('***           Cattura PCAP disabilitata.\n')
        info('***           Per abilitarla installare tshark mediante package manager (zypper, apt, ecc.)\n')
    else:
        tool = capture_cmd[0]

        # -------------------------------------------------------------------
        # [PACKET CAPTURE — Passo 2] Avvio del processo di cattura
        # -------------------------------------------------------------------
        # h1.popen() è il metodo di Mininet che lancia un sottoprocesso
        # nel network namespace di h1 mediante mnexec internamente.
        # Il punto chiave è il fenomeno per il quale, da dentro quel namespace, h1-eth0
        # è l'unica interfaccia presente, quindi il tool non può
        # accidentalmente fare sniffing del traffico di altri host.
        #
        # NOTA DI DEBUG:
        # Inizialmente veniva usato subprocess.DEVNULL per mantenere pulito il prompt interattivo di Mininet.
        # Tuttavia, tshark falliva silenziosamente senza generare il PCAP.
        # Si è quindi trasformato da DEVNULL a PIPE per catturare e ispezionare eventuali errori e output.
        info(f'*** [CAPTURE] Avvio {tool} su {CAPTURE_IFACE} '
              f'| filtro: "{BPF_FILTER}" | output: {PCAP_OUTPUT}\n')

        capture_proc = h1.popen(
            capture_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        info(f'*** [CAPTURE] {tool} in esecuzione (PID={capture_proc.pid})\n')
        info( '*** [CAPTURE] La cattura si fermerà automaticamente '
              'all\'uscita dalla CLI (exit o Ctrl+C).\n\n')

    # -----------------------------------------------------------------------
    # [PACKET CAPTURE — Passo 3] try/finally: prevenzione zombie
    # -----------------------------------------------------------------------
    # Il codice nel blocco finally viene
    # sempre eseguito in tutti i casi, come l'uscita normale, l'interruzione via Ctrl+C, qualsiasi eccezione, ecc.
    # Necessario perché un Ctrl+C lascerebbe tshark/tcpdump in esecuzione in background,
    # corrompendo il file o troncandolo in Wireshark.
    try:
        CLI(net)

    finally:
        # --- Terminazione del processo di cattura ---
        if capture_proc is not None:
            info(f'\n*** [CAPTURE] Arresto cattura (PID={capture_proc.pid})...\n')

            # Primo tentativo: SIGTERM (terminazione ordinata).
            # tshark e tcpdump gestiscono SIGTERM facendo il flush dei buffer
            # e scrivendo il trailer pcap/pcapng prima di uscire.
            # Questo garantisce che il file sia apribile senza errori
            # in Wireshark ("a valid capture file was expected here").
            capture_proc.terminate()

            try:
                capture_proc.wait(timeout=CAPTURE_TERM_TIMEOUT)
                info(f'*** [CAPTURE] Processo terminato ordinatamente.\n')
            except subprocess.TimeoutExpired:
                # Rimedio: SIGKILL se il processo non risponde entro
                # CAPTURE_TERM_TIMEOUT secondi. Il file potrebbe essere
                # parzialmente troncato, ma almeno non rimangono zombie.
                info(f'*** [CAPTURE] Timeout SIGTERM ({CAPTURE_TERM_TIMEOUT}s) '
                     f'-> invio SIGKILL...\n')
                capture_proc.kill()
                capture_proc.wait()  # attesa bloccante senza timeout dopo SIGKILL
                info(f'*** [CAPTURE] Processo terminato forzatamente (SIGKILL).\n')

            # --- Salvataggio automatico e modifica permessi all'utente ---
            final_pcap = 'server_capture.pcap'
            if os.path.exists(PCAP_OUTPUT):
                # Spostamento del file da /tmp/ alla cartella del project work
                shutil.move(PCAP_OUTPUT, final_pcap)

                # Restituzione della proprietà del file all'utente che ha invocato sudo
                sudo_user = os.environ.get('SUDO_USER')
                if sudo_user:
                    user_info = pwd.getpwnam(sudo_user)
                    os.chown(final_pcap, user_info.pw_uid, user_info.pw_gid)

                info(f'*** [CAPTURE] File salvato e sbloccato in: {os.path.abspath(final_pcap)}\n')
            else:
                info(f'*** [CAPTURE] ERRORE: File {PCAP_OUTPUT} non trovato.\n')
            # ----------------------------------------------------

            info('*** [CAPTURE] Comandi di analisi:\n')
            info(f'***             wireshark {final_pcap}\n')
            info(f'***             tshark -r {final_pcap} -T fields '
                 f'-e ip.src -e http.request.uri\n')

            # --- Spegnimento della rete ---
        net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build_topology()
