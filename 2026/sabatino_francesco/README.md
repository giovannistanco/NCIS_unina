# SDN-based-Intrusion-Detection-Mitigation-System
ARP Spoofing e Port Scanning Detection in ambiente SDN (Mininet + Ryu, OpenFlow 1.3)

## 1. Prerequisiti
- **OS:** Ubuntu 22.04 LTS (VirtualBox, min. 2 vCPU, 4GB RAM, 25GB disco)
- Accesso `sudo` abilitato

---

## 2. Pacchetti Base e Strumenti di Test
```bash
sudo apt update
sudo apt install -y vim git python3-pip d-itg nload dsniff nmap
```

---

## 3. Installazione Mininet
```bash
git clone https://github.com/mininet/mininet
cd mininet
git checkout -b mininet-2.3.0 2.3.0
cd ..
sudo PYTHON=python3 mininet/util/install.sh -nv
```

---

## 4. Installazione e Patch Ryu (Python 3.10)
Per risolvere le incompatibilità di Ryu ed Eventlet su Ubuntu 22.04 / Python 3.10:

```bash
# Installazione Ryu e aggiornamento dnspython
sudo pip install ryu
sudo pip install --upgrade dnspython

# Patch modulo wsgi per compatibilità eventlet
sudo python3 -c "import re,ryu,os; path=os.path.join(os.path.dirname(ryu.__file__),'app','wsgi.py'); content=open(path).read(); pattern=re.compile(r'^([ \t]*)from eventlet\.wsgi import ALREADY_HANDLED\s*$', re.MULTILINE); repl=lambda m: m.group(1)+'try:\n'+m.group(1)+'    from eventlet.wsgi import ALREADY_HANDLED\n'+m.group(1)+'except ImportError:\n'+m.group(1)+'    ALREADY_HANDLED = None'; new_content,n=pattern.subn(repl, content); open(path,'w').write(new_content) if n>0 else None; print('Patch applicata' if n>0 else 'Gia patchato')"
```

---

## 5. Avvio dell'Ambiente

### Terminale 1 — Controller Ryu
```bash
cd ~/sdn_project
ryu-manager security_controller.py
```

### Terminale 2 — Topologia Mininet
```bash
cd ~/sdn_project
sudo python3 topology.py
```

---

## 6. Test e Simulazione Attacchi (CLI Mininet)
```bash
# Verifica raggiungibilità host
mininet> pingall
