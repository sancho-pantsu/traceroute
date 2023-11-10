import socket
from typing import Callable


class WhoisServer:
    def __init__(self, addr: str, mkQuery: Callable[[str], str], originName: str):
        self.address = addr
        self.makeQuery = mkQuery
        self.originName = originName


class WhoisResponse:
    def __init__(self, data: bytes, server: WhoisServer):
        self.rawData = data
        self.data = WhoisResponse.respToDict(data)
        self.originName = server.originName

    def getValue(self, key: str) -> str:
        if key in self.data:
            return self.data[key]
        return None

    @property
    def found(self):
        return self.getValue(self.originName) is not None

    @staticmethod
    def respToDict(data: bytes) -> dict:
        res = {}
        for line in data.decode().splitlines():
            if line.startswith('%') or line.strip() == '':
                continue
            delIndex = line.find(':')
            key, val = line[:delIndex].strip(), line[delIndex + 1:].strip()
            res[key] = val
        return res


WHOIS_SERVERS = [
    WhoisServer('whois.ripe.net', lambda ip: f'{ip}\r\n', 'origin'),
    WhoisServer('whois.iana.org', lambda ip: f'{ip}\r\n', 'origin'),
    WhoisServer('whois.arin.net', lambda ip: f'n + {ip}\r\n', 'OriginAS'),
]


def whois(ip: str) -> WhoisResponse:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        for server in WHOIS_SERVERS:
            sock.connect((server.address, 43))
            sock.sendall(server.makeQuery(ip).encode())

            total_data = b''
            data = sock.recv(4096)
            while data:
                total_data += data
                data = sock.recv(4096)

            response = WhoisResponse(total_data, server)
            if response.found:
                return response

    return None
