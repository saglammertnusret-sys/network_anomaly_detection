import math
from dataclasses import dataclass

FEATURES = ['packets_per_second', 'bytes_per_second', 'mean_packet_bytes',
            'std_packet_bytes', 'unique_addresses', 'unique_ports',
            'tcp_fraction', 'udp_fraction', 'syn_fraction']
FIELDS = ['frame.time_epoch', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src',
          'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
          'udp.dstport', 'tcp.flags.syn']
CSV_FIELDS = ['window_start', 'window_seconds', *FEATURES]

@dataclass
class Packet:
    timestamp: float
    length: int
    source: str
    destination: str
    ports: tuple
    tcp: bool
    udp: bool
    syn: bool

def parse_packet(line):
    fields = line.rstrip('\r\n').split('\t')
    if len(fields) != len(FIELDS):
        raise ValueError('TShark field count differs from the expected schema.')
    timestamp, length = float(fields[0]), int(fields[1])
    if not math.isfinite(timestamp) or length < 0:
        raise ValueError('Invalid packet timestamp or length.')
    source, destination = fields[2] or fields[4], fields[3] or fields[5]
    if not source or not destination:
        raise ValueError('Expected an IPv4 or IPv6 packet.')
    ports = tuple(int(value) for value in fields[6:10] if value)
    if any(port < 0 or port > 65535 for port in ports):
        raise ValueError('Invalid transport port.')
    tcp, udp = bool(fields[6] or fields[7]), bool(fields[8] or fields[9])
    syn = fields[10].lower() in ('1', 'true', '0x0001')
    return Packet(timestamp, length, source, destination, ports, tcp, udp, syn)

class Window:
    def __init__(self):
        self.count = self.bytes = self.squares = self.tcp = self.udp = self.syn = 0
        self.addresses, self.ports = set(), set()

    def add(self, packet):
        self.count += 1
        self.bytes += packet.length
        self.squares += packet.length ** 2
        self.tcp += packet.tcp
        self.udp += packet.udp
        self.syn += packet.syn
        self.addresses.update((packet.source, packet.destination))
        self.ports.update(packet.ports)

    def row(self, start, seconds):
        if seconds <= 0:
            raise ValueError('Window duration must be positive.')
        mean = self.bytes / self.count if self.count else 0
        variance = max(0, self.squares / self.count - mean ** 2) if self.count else 0
        return dict(zip(CSV_FIELDS, [start, seconds, self.count / seconds,
                    self.bytes / seconds, mean, math.sqrt(variance),
                    len(self.addresses), len(self.ports),
                    self.tcp / self.count if self.count else 0,
                    self.udp / self.count if self.count else 0,
                    self.syn / self.count if self.count else 0]))
