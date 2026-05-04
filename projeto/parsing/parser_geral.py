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
        self.packet_number = None  # atribuído pelo Dispatcher após filtros

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
        elif self.packet.haslayer("IPv6"):
            ipv6 = self.packet["IPv6"]
            self.src_ip = ipv6.src
            self.dst_ip = ipv6.dst

    @abstractmethod
    def _parse(self):
        """Cada subclasse implementa o parsing específico."""
        pass

    @abstractmethod
    def summary(self):
        """Retorna uma linha-resumo do pacote."""
        pass

    def header(self):
        """Cabeçalho comum — alinhado com imprimir_cabecalho()."""
        num = f"#{self.packet_number}" if self.packet_number is not None else "#?"
        return (f"{num:<5} {self.timestamp:<26} {self.interface:<8} "
                f"{self.protocol_name:<6} {str(self.length) + 'B':<9}")