import scapy.all as scapy
from parsing.parser_geral import ProtocolParser


# Tipos de record DNS mais comuns
TIPO_RECORD = {
    1:   "A",        # IPv4
    2:   "NS",       # Name Server
    5:   "CNAME",    # Alias
    6:   "SOA",      # Start Of Authority
    12:  "PTR",      # Reverse DNS
    15:  "MX",       # Mail Exchange
    16:  "TXT",      # Text
    28:  "AAAA",     # IPv6
    33:  "SRV",      # Service
    41:  "OPT",      # EDNS
    65:  "HTTPS",    # HTTPS RR (mais recente)
}


class DNS(ProtocolParser):
    protocol_name = "DNS"

    def _parse(self):
        self.qr = None           # 0 = query, 1 = response
        self.query_name = None   # domínio consultado
        self.query_type = None   # tipo de record (A, AAAA, etc.)
        self.transaction_id = None
        self.answers = []        # lista de respostas, se for reply

        # Portas UDP (para mostrar no summary se quisermos)
        if scapy.UDP in self.packet:
            udp = self.packet[scapy.UDP]
            self.sport = udp.sport
            self.dport = udp.dport
        else:
            self.sport = None
            self.dport = None

        if scapy.DNS in self.packet:
            dns = self.packet[scapy.DNS]
            self.qr = dns.qr
            self.transaction_id = dns.id

            # Nome e tipo da query (vem no campo qd se qdcount > 0)
            if dns.qdcount > 0 and dns.qd is not None:
                qd = dns.qd
                try:
                    self.query_name = qd.qname.decode(errors="replace").rstrip(".")
                except Exception:
                    self.query_name = str(qd.qname)
                self.query_type = TIPO_RECORD.get(qd.qtype, f"Type{qd.qtype}")

            # Se for resposta, extrair os answers
            if self.qr == 1 and dns.ancount > 0 and dns.an is not None:
                # Scapy pode devolver vários answers encadeados
                an = dns.an
                while an is not None:
                    try:
                        rdata = an.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="replace")
                        self.answers.append((
                            TIPO_RECORD.get(an.type, f"Type{an.type}"),
                            str(rdata)
                        ))
                    except Exception:
                        pass
                    an = an.payload if an.payload and an.payload.name != "NoPayload" else None

    def summary(self):
        if self.qr == 0:
            # Query
            return (f"{self.src_ip}:{self.sport} -> {self.dst_ip}:{self.dport} | "
                    f"Query id={self.transaction_id} {self.query_type} {self.query_name}")
        elif self.qr == 1:

            if self.answers:
                # junta os primeiros 3 answers para não encher o ecrã
                ans_str = ", ".join(f"{t}={v}" for t, v in self.answers[:3])
                if len(self.answers) > 3:
                    ans_str += f", ... (+{len(self.answers)-3} more)"
            else:
                ans_str = "no answers"
            return (f"{self.src_ip}:{self.sport} -> {self.dst_ip}:{self.dport} | "
                    f"Response id={self.transaction_id} {self.query_name} -> {ans_str}")
        else:
            return f"{self.src_ip} -> {self.dst_ip} | DNS (unknown qr)"

    def __str__(self):
        return f"{self.header()} | {self.summary()}"