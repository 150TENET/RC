import scapy.all as scapy
from parsing.parser_geral import ProtocolParser


# Portas bem conhecidas (apenas para anotar no output)
PORTAS_CONHECIDAS = {
    20:    "FTP-data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    465:   "SMTPS",
    587:   "SMTP-sub",
    993:   "IMAPS",
    995:   "POP3S",
    3306:  "MySQL",
    5432:  "Postgres",
    6379:  "Redis",
    8080:  "HTTP-alt",
    8443:  "HTTPS-alt",
}


class TCP(ProtocolParser):
    protocol_name = "TCP"

    # Bits das flags TCP — para descodificar
    FLAGS_BITS = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]

    def _parse(self):
        self.sport = None
        self.dport = None
        self.seq = None
        self.ack = None
        self.window = None
        self.flags_raw = 0
        self.flags_str = ""
        self.payload_len = 0

        if scapy.TCP in self.packet:
            tcp = self.packet[scapy.TCP]
            self.sport = tcp.sport
            self.dport = tcp.dport
            self.seq = tcp.seq
            self.ack = tcp.ack
            self.window = tcp.window
            self.flags_raw = int(tcp.flags)

            # Descodifica as flags ativas
            ativas = [nome for bit, nome in self.FLAGS_BITS if self.flags_raw & bit]
            self.flags_str = "+".join(ativas) if ativas else "(none)"

            # Tamanho do payload TCP (dados da camada de aplicação)
            try:
                self.payload_len = len(bytes(tcp.payload))
            except Exception:
                self.payload_len = 0

    def _nome_porta(self, porta):
        nome = PORTAS_CONHECIDAS.get(porta)
        return f"{nome}({porta})" if nome else str(porta)

    def _interpretar_flags(self):
        """Devolve uma descrição curta do propósito do pacote, baseada nas flags."""
        f = self.flags_raw
        SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08

        if f & RST:
            return "[RESET]"
        if (f & SYN) and (f & ACK):
            return "[handshake 2/3 - SYN+ACK]"
        if f & SYN:
            return "[handshake 1/3 - SYN]"
        if (f & FIN) and (f & ACK):
            return "[close]"
        if f & FIN:
            return "[close]"
        if (f & PSH) and (f & ACK) and self.payload_len > 0:
            return f"[data {self.payload_len}B]"
        if f & ACK and self.payload_len == 0:
            return "[ACK]"
        if self.payload_len > 0:
            return f"[data {self.payload_len}B]"
        return ""

    def summary(self):
        src = self._nome_porta(self.sport)
        dst = self._nome_porta(self.dport)
        descr = self._interpretar_flags()
        return (f"{self.src_ip}:{src} -> {self.dst_ip}:{dst} | "
                f"flags={self.flags_str} seq={self.seq} ack={self.ack} "
                f"win={self.window} {descr}")

    def __str__(self):
        return f"{self.header()} | {self.summary()}"