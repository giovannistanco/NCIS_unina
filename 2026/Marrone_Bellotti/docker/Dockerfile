# Ryu è abbandonato e richiede Python <=3.9 (su 3.10+ eventlet rompe su socket.timeout).
# Debian 11 (bullseye) = Python 3.9.2 di sistema + Mininet 2.3.0 + OVS + D-ITG già in apt.
FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive

# Tool di rete/SDN da apt (Mininet, OVS, generatori di traffico, sniffer)
# Debian 11 e' a fine LTS (ago 2026): su deb.debian.org l'indice di bullseye-security
# punta a pacchetti rimossi (404). Si usa lo snapshot datato gia' indicato (commentato)
# nell'immagine base: stesse versioni dell'immagine, build riproducibile.
RUN sed -i -e '/^deb /d' -e 's/^# deb http:\/\/snapshot/deb http:\/\/snapshot/' /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until "false"; Acquire::Retries "5";' > /etc/apt/apt.conf.d/99snapshot \
 && apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates build-essential python3 python3-dev python3-pip \
      iproute2 iputils-ping net-tools tcpdump tshark nload \
      mininet openvswitch-switch openvswitch-common \
      iperf iperf3 d-itg hping3 curl procps \
 && rm -rf /var/lib/apt/lists/*

# Ryu via pip: setuptools 58 (ultimo compatibile col setup.py legacy) + no-build-isolation
# così pip non rigenera un ambiente con setuptools recente che romperebbe la build.
# eventlet 0.30.2 = versione compatibile con Ryu 4.34 su Python 3.9.
# Tutte le versioni (ryu, eventlet, scikit-learn, ...) sono fissate in requirements.txt:
# model.joblib e' un pickle legato alla versione di scikit-learn.
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir "pip<24.1" "setuptools==58.2.0" wheel \
 && python3 -m pip install --no-cache-dir --no-build-isolation -r /tmp/requirements.txt

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
