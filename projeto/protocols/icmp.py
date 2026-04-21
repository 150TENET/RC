import scapy.all as scapy
from protocols.parser_geral import ProtocolParser


class ICMP(ProtocolParser):
    protocol_name = "ICMP"

    TYPE_MAP = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded (TTL=0)",
        13: "Timestamp Request",
        14: "Timestamp Reply",
    }

    def _parse(self):
        self.type = None
        self.code = None
        self.id = None
        self.seq = None

        if scapy.ICMP in self.packet:
            icmp = self.packet[scapy.ICMP]
            self.type = icmp.type
            self.code = icmp.code
            self.id = icmp.id
            self.seq = icmp.seq

    def summary(self):
        type_name = self.TYPE_MAP.get(self.type, f"Type {self.type}")
        return (f"{self.src_ip} -> {self.dst_ip} | "
                f"{type_name} (code={self.code}, id={self.id}, seq={self.seq})")

    def __str__(self):
        return f"{self.header()} | {self.summary()}"