import socket


class WhoisResponse:
    def __init__(self, data: bytes):
        self.rawData = data
        self.data = WhoisResponse.respToDict(data)

    def getValue(self, key: str) -> str:
        if key in self.data:
            return self.data[key]
        return None

    @property
    def found(self):
        return self.getValue('origin') is not None

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


def whois(ip: str, whoisServerAddress: str = 'icmp')\
        -> WhoisResponse:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((whoisServerAddress, 43))
        sock.sendall(f'{ip}\r\n'.encode())

        total_data = b''
        data = sock.recv(4096)
        while data:
            total_data += data
            data = sock.recv(4096)

        return WhoisResponse(total_data)
