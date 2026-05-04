import scapy.all as scapy
from parsing.parser_geral import ProtocolParser


# Mapa dos números de protocolo IP para nomes (RFC 5237)
PROTOCOLOS_IP = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}


class IPv4(ProtocolParser):
    protocol_name = "IPv4"

    def _parse(self):
        self.proto_num = None
        self.proto_name = None
        self.ttl = None
        self.id = None
        self.flags_raw = 0
        self.flags_str = ""
        self.frag_offset = 0
        self.is_fragment = False
        self.frag_ref = None  # packet_number do primeiro fragmento desta sequência

        if scapy.IP in self.packet:
            ip = self.packet[scapy.IP]
            self.proto_num = ip.proto
            self.proto_name = PROTOCOLOS_IP.get(ip.proto, f"proto={ip.proto}")
            self.ttl = ip.ttl
            self.id = ip.id
            self.flags_raw = int(ip.flags)
            self.frag_offset = ip.frag

            # Decode flags IP: bit 0 = reservado, bit 1 = DF, bit 2 = MF
            flags_ativas = []
            if self.flags_raw & 0x02:
                flags_ativas.append("DF")
            if self.flags_raw & 0x01:
                flags_ativas.append("MF")
            self.flags_str = "+".join(flags_ativas) if flags_ativas else "(none)"

            # É um fragmento se: tem MF ativo OU tem offset > 0
            self.is_fragment = (self.flags_raw & 0x01) != 0 or self.frag_offset > 0

    def summary(self):
        base = (f"{self.src_ip} -> {self.dst_ip} | "
                f"proto={self.proto_name} ttl={self.ttl} id={self.id}")

        if self.is_fragment:
            # offset vem em unidades de 8 bytes, multiplica para mostrar em bytes
            offset_bytes = self.frag_offset * 8
            base += f" | FRAGMENT flags={self.flags_str} offset={offset_bytes}B"

            # Fragmentos não-iniciais mostram referência ao primeiro fragmento
            if self.frag_offset > 0:
                if self.frag_ref is not None:
                    base += f" (frag of pkt #{self.frag_ref})"
                else:
                    base += " (frag of pkt ?)"

        return base

    def __str__(self):
        return f"{self.header()} | {self.summary()}"