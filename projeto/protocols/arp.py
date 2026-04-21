import scapy.all as scapy
from parsing.parser_geral import ProtocolParser

class ARP(ProtocolParser):
    protocol_name = "ARP"

    OP_MAP = {
        1: "Request",
        2: "Reply",
    }

    def _parse(self):
        self.op = None
        self.hwsrc = None   # MAC do emissor
        self.hwdst = None   # MAC do destinatário
        self.psrc = None    # IP do emissor
        self.pdst = None    # IP do destinatário

        if scapy.ARP in self.packet:
            arp = self.packet[scapy.ARP]
            self.op = arp.op
            self.hwsrc = arp.hwsrc
            self.hwdst = arp.hwdst
            self.psrc = arp.psrc
            self.pdst = arp.pdst

    def summary(self):
        op_name = self.OP_MAP.get(self.op, f"Op {self.op}")

        if self.op == 1:  # Request
            return f"Who has {self.pdst}? Tell {self.psrc} ({self.hwsrc})"
        elif self.op == 2:  # Reply
            return f"{self.psrc} is at {self.hwsrc}"
        else:
            return f"{op_name} | {self.psrc} -> {self.pdst}"

    def __str__(self):
        return f"{self.header()} | {self.summary()}"
