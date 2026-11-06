# experiments/run_attack.sh — riferimento dei comandi per la CLI mininet (uso MANUALE).
# Per l'esperimento riproducibile automatico usare invece: experiments/scenario.py
#
# 1) Server (hsrv): riceve UDP (D-ITG) e TCP (iperf legittimo)
#    hsrv ITGRecv -l /tmp/recv.log &
#    hsrv iperf -s -p 5002 &                       # TCP legittimo
# 2) Utente legittimo u1 -> server (TCP, 100s, log per-secondo)
#    u1 iperf -c 10.0.0.100 -p 5002 -t 100 -i 1 > /tmp/u1_tcp.log &
# 3) Attaccante a1 -> server (UDP flood con D-ITG)
#    a1 ITGSend experiments/itg_flows/attack.itg -l /tmp/send.log &
# 4) Decodifica log lato server
#    hsrv ITGDec /tmp/recv.log > experiments/recv.txt
#
# Nota: scenario.py usa iperf UDP (al posto di D-ITG) per la generazione del flood,
# con una fase baseline + flood necessaria a far rilevare lo spike al detector adattivo.
