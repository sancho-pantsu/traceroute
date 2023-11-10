from scapy.packet import Packet
from scapy.sendrecv import sr1

import whois
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6


class Tracer:
    def __init__(self, dst: str, timeout: int = 2, protocol: str = 'icmp', dport: int = None,
                 maxCount: int = None, verbose: bool = False):
        self.dst = dst
        self.timeout = timeout
        self.protocol = protocol
        self.dport = dport
        self.maxCount = maxCount
        self.verbose = verbose

    @property
    def isV6Ip(self):
        return ':' in self.dst

    @property
    def transportLayer(self) -> Packet:
        if self.protocol == 'tcp':
            return TCP(dport=self.dport)
        elif self.protocol == 'udp':
            return UDP(dport=self.dport)
        else:
            return ICMP(id=1)

    def sr(self, packet: Packet):
        return sr1(packet, timeout=self.timeout, verbose=False)

    def makeScanPacket(self, ttl: int) -> Packet:
        if self.isV6Ip:
            return IPv6(dst=self.dst, hlim=ttl) / self.transportLayer
        return IP(dst=self.dst, ttl=ttl) / self.transportLayer

    def out(self, count: int, startTime: float, rsp: Packet):
        if rsp is None:
            res = f'{count}\t{"*"}\t-\t'
            if self.verbose:
                res += '-\t'
            print(res)
            return
        res = f'{count}\t{rsp.src}\t{int(rsp.time - startTime)}\t'
        if self.verbose:
            asys = whois.whois(rsp.src).getValue('origin') or '-'
            res += f'{asys}\t'

    def trace(self):
        count = 0
        while self.maxCount is None or count < self.maxCount:
            count += 1

            scanPacket = self.makeScanPacket(count)
            rsp = self.sr(scanPacket)

            self.out(count + 1, scanPacket.time, rsp)

            if rsp is None:
                continue

            if (self.protocol == 'icmp' and rsp.type == 0 or
                    (self.protocol == 'tcp' or self.protocol == 'udp') and rsp.type == 3):
                break
