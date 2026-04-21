from abc import ABC, abstractmethod
import scapy.all as scapy


class ProtocolParser(ABC):
    """
    Classe base para todos os parsers de protocolos.
    Cada parser específico (ICMP, ARP, TCP, ...) herda desta
    e implementa o método _parse() com a lógica específica.
    """

    protocol_name = "UNKNOWN"

    def __init__(self, packet):
        self.packet = packet

        self.timestamp = getattr(packet, "sniff_timestamp", "")
        self.interface = getattr(packet, "sniff_interface", "")
        self.length = len(packet)

        self.src_mac = None
        self.dst_mac = None
        self.src_ip = None
        self.dst_ip = None

        self._parse_common()
        self._parse()

    def _parse_common(self):
        """Extrai MACs e IPs se presentes."""
        if scapy.Ether in self.packet:
            self.src_mac = self.packet[scapy.Ether].src
            self.dst_mac = self.packet[scapy.Ether].dst
        if scapy.IP in self.packet:
            self.src_ip = self.packet[scapy.IP].src
            self.dst_ip = self.packet[scapy.IP].dst

    @abstractmethod
    def _parse(self):
        """Cada subclasse implementa o parsing específico."""
        pass

    @abstractmethod
    def summary(self):
        """Retorna uma linha-resumo do pacote."""
        pass

    def header(self):
        """Cabeçalho comum — formato tipo tcpdump."""
        return (f"[{self.timestamp}] {self.interface} "
                f"{self.protocol_name:<6} {self.length}B")