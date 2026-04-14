
import scapy.all as scapy

class ICMP:

    def __init__(self, packet):
        self.packet = packet
        self.type = None
        self.code = None
        self.checksum = None
        self.id = None
        self.seq = None
        self._parse()

    def _parse(self):
        if scapy.ICMP in self.packet:
            icmp_layer = self.packet[scapy.ICMP]
            self.type = icmp_layer.type
            self.code = icmp_layer.code
            self.id = icmp_layer.id
            self.seq = icmp_layer.seq

    def __str__(self):
        type_map = {
            0: "Echo Reply",
            8: "Echo Request",
            3: "Destination Unreachable",
            11: "Time Exceeded (TTL=0)"
        }
        type_name = type_map.get(self.type, str(self.type))

        return (f"Pacote ICMP:\n"
                f"  Tipo: {type_name}\n"
                f"  Código: {self.code}\n"
                f"  ID: {self.id}\n"
                f"  Sequência: {self.seq}\n"
        )