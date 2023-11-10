from scapy.sendrecv import sr1

from scapy.layers.inet import IP, ICMP, TCP, UDP

packet = IP(dst='8.8.8.8', ttl=1) / UDP(dport=1337)
rsp = sr1(packet, timeout=5, verbose=True)
if rsp is None:
    print('no response')
else:
    res = f'{1}\t{rsp.src}\t{int(rsp.time - packet.time)}\t'
