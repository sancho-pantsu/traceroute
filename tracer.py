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
            res = f'{str(count): <5}{"*": <16}{"-": <8}'
            if self.verbose:
                res += f'{"-"}'
            print(res)
            return
        res = f'{count: <5}{rsp.src: <16}{str(int((rsp.time - startTime) * 1000)) + " ms": <8}'
        if self.verbose:
            whoisResp = whois.whois(rsp.src)
            asys = whoisResp.getValue(whoisResp.originName) if (whoisResp
                                                                and whoisResp.found
                                                                and whoisResp.getValue(whoisResp.originName)) \
                else '-'
            res += f'{asys}'
        print(res)

    def trace(self):
        count = 0
        while self.maxCount is None or count < self.maxCount:
            count += 1

            scanPacket = self.makeScanPacket(count)
            rsp = self.sr(scanPacket)
            if rsp is None:
                rsp = self.sr(scanPacket)

            self.out(count, scanPacket.time, rsp)

            if rsp is None:
                continue

            if self.protocol == 'icmp' and rsp.type == 0:
                break
            if self.protocol == 'tcp' and rsp.haslayer(TCP) or self.protocol == 'udp' and rsp.haslayer(UDP):
                break
