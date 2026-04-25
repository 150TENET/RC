import scapy.all as scapy
from parsing.parser_geral import ProtocolParser


# Portas bem conhecidas (apenas para anotar no output)
PORTAS_CONHECIDAS = {
    53:   "DNS",
    67:   "DHCP(srv)",
    68:   "DHCP(cli)",
    69:   "TFTP",
    123:  "NTP",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    161:  "SNMP",
    443:  "QUIC",     # HTTP/3
    500:  "IKE",
    514:  "Syslog",
    1900: "SSDP",
    5353: "mDNS",
    5355: "LLMNR",
}


class UDP(ProtocolParser):
    protocol_name = "UDP"

    def _parse(self):
        self.sport = None
        self.dport = None
        self.payload_len = None

        if scapy.UDP in self.packet:
            udp = self.packet[scapy.UDP]
            self.sport = udp.sport
            self.dport = udp.dport
            # Tamanho do payload UDP (len - 8 bytes de cabeçalho)
            self.payload_len = max(0, udp.len - 8)

    def _nome_porta(self, porta):
        """Devolve 'nome(porta)' se a porta for conhecida, senão só o número."""
        nome = PORTAS_CONHECIDAS.get(porta)
        return f"{nome}({porta})" if nome else str(porta)

    def summary(self):
        src = self._nome_porta(self.sport)
        dst = self._nome_porta(self.dport)
        return (f"{self.src_ip}:{src} -> {self.dst_ip}:{dst} | "
                f"payload={self.payload_len}B")

    def __str__(self):
        return f"{self.header()} | {self.summary()}"