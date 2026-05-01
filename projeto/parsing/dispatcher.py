import scapy.all as scapy
from protocols.icmp import ICMP
from protocols.arp import ARP
from protocols.udp import UDP
from protocols.dns import DNS
from protocols.tcp import TCP
from protocols.ipv4 import IPv4

# Códigos ANSI de cor por protocolo
CORES = {
    "ICMP": "\033[96m",   # ciano
    "TCP":  "\033[92m",   # verde
    "UDP":  "\033[93m",   # amarelo
    "ARP":  "\033[95m",   # magenta
    "DNS":  "\033[94m",   # azul
    "IPv4": "\033[91m",   # vermelho
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def imprimir_cabecalho():
    linha = (
        f"{'DATA/HORA':<26} {'IFACE':<8} {'PROTO':<6} "
        f"{'TAMANHO':<9} {'DETALHE'}"
    )
    separador = "-" * len(linha)
    print(BOLD + linha + RESET)
    print(separador)


class Dispatcher:
    """
    Recebe pacotes brutos do scapy, identifica o protocolo
    e entrega-os ao parser apropriado.
    """

    def __init__(self, protocol_filter=None, ip_filter=None, mac_filter=None, frag_filter=None,
                live=True, logger=None, conv_tracker=None, talkers_tracker=None, stream_tracker=None):
        self.protocol_filter = (
            [p.upper() for p in protocol_filter] if protocol_filter else None
        )
        self.ip_filter = ip_filter
        self.mac_filter = mac_filter.lower() if mac_filter else None
        self.frag_filter = frag_filter or {}
        self.live = live
        self.logger = logger
        self.conv_tracker = conv_tracker
        self.talkers_tracker = talkers_tracker
        self.stream_tracker = stream_tracker
        self.stats = {}
        self.hierarchy = {}  # Hierarquia de protocolos

        if self.live:
            imprimir_cabecalho()

    def identificarProtocolo(self, packet):
        """Identifica o protocolo e retorna o parser instanciado."""
        if packet.haslayer(scapy.ARP):
            return ARP(packet)
        if packet.haslayer(scapy.ICMP):
            return ICMP(packet)
        if packet.haslayer(scapy.DNS):
            return DNS(packet)
        if packet.haslayer(scapy.TCP):
            return TCP(packet)
        if packet.haslayer(scapy.UDP):
            return UDP(packet)
        if packet.haslayer(scapy.IP):
            return IPv4(packet)
        return None

    def _extrair_hierarquia_protocolos(self, packet):
        """Extrai a cadeia de protocolos do pacote (hierarquia)."""
        protocolos = []

        # Camada 2
        if packet.haslayer(scapy.Ether):
            protocolos.append("Ethernet")

        # Camada 3
        if packet.haslayer(scapy.ARP):
            protocolos.append("ARP")
        elif packet.haslayer(scapy.IP):
            protocolos.append("IPv4")

            # Camada 4
            if packet.haslayer(scapy.TCP):
                protocolos.append("TCP")
            elif packet.haslayer(scapy.UDP):
                protocolos.append("UDP")
            elif packet.haslayer(scapy.ICMP):
                protocolos.append("ICMP")

            # Camada 5+
            if packet.haslayer(scapy.DNS):
                protocolos.append("DNS")

        return " → ".join(protocolos) if protocolos else "Desconhecido"

    def _passa_filtro_fragmentacao(self, packet):
        """
        Aplica os filtros de fragmentação ao pacote.
        Retorna True se o pacote deve ser mostrado, False caso contrário.
        """
        f = self.frag_filter
        if not f:
            return True  # sem filtros de fragmentação ativos

        # Extrai informação de fragmentação do cabeçalho IP
        if not packet.haslayer(scapy.IP):
            # Pacote não-IP nunca passa filtros de fragmentação específicos
            # (mas passa em --no-fragments, porque tecnicamente "não é fragmento")
            if f.get("no_fragments"):
                return True
            return False

        ip = packet[scapy.IP]
        flags = int(ip.flags)
        offset = ip.frag
        is_mf = (flags & 0x01) != 0          # More Fragments
        is_fragment = is_mf or offset > 0    # qualquer fragmento

        # --no-fragments: rejeita qualquer fragmento
        if f.get("no_fragments") and is_fragment:
            return False

        # --only-fragments: rejeita pacotes não-fragmentados
        if f.get("only_fragments") and not is_fragment:
            return False

        # --frag-id: rejeita fragmentos com ID diferente do pedido
        if f.get("frag_id") is not None:
            if not is_fragment or ip.id != f["frag_id"]:
                return False

        # --frag-offset: rejeita fragmentos com offset diferente do pedido
        # (offset no header está em unidades de 8 bytes; comparamos em bytes)
        if f.get("frag_offset") is not None:
            if not is_fragment or (offset * 8) != f["frag_offset"]:
                return False

        # --first-fragment: só primeiro fragmento (offset=0 e MF=1)
        if f.get("first_fragment"):
            if not (offset == 0 and is_mf):
                return False

        # --last-fragment: só último fragmento (MF=0 e offset>0)
        if f.get("last_fragment"):
            if not (not is_mf and offset > 0):
                return False

        return True

    def processar(self, packet):
        """Callback a ser passado ao Captura."""
        parser = self.identificarProtocolo(packet)

        if parser is None:
            return

        # Aplicar todos os filtros antes de processar
        if self.protocol_filter and parser.protocol_name not in self.protocol_filter:
            return

        if self.ip_filter:
            if parser.src_ip != self.ip_filter and parser.dst_ip != self.ip_filter:
                return

        if self.mac_filter:
            src = (parser.src_mac or "").lower()
            dst = (parser.dst_mac or "").lower()
            if src != self.mac_filter and dst != self.mac_filter:
                return

        if not self._passa_filtro_fragmentacao(packet):
            return

        # Se passou em todos os filtros, contar e imprimir
        self.stats[parser.protocol_name] = self.stats.get(parser.protocol_name, 0) + 1

        # Registar hierarquia de protocolos
        hierarquia = self._extrair_hierarquia_protocolos(packet)
        self.hierarchy[hierarquia] = self.hierarchy.get(hierarquia, 0) + 1

        # Registar conversa
        if self.conv_tracker:
            self.conv_tracker.registar(parser)

        # Registar top talker
        if self.talkers_tracker:
            self.talkers_tracker.registar(parser)

        # Registar stream TCP
        if self.stream_tracker:
            self.stream_tracker.registar(parser)

        if self.live:
            cor = CORES.get(parser.protocol_name, "\033[97m")
            print(cor + str(parser) + RESET)

        if self.logger:
            self.logger.registar(parser)

    def imprimirEstatisticas(self):
        if not self.stats:
            print("\nNenhum pacote capturado.")
            return
        print("\n" + BOLD + "=== Estatísticas da captura ===" + RESET)
        total = sum(self.stats.values())
        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            pct = 100 * count / total
            cor = CORES.get(proto, "\033[97m")
            print(f"{cor}  {proto:<6} {count:>6}  ({pct:.1f}%){RESET}")
        print(BOLD + f"  {'TOTAL':<6} {total:>6}" + RESET)

    def imprimirHierarquia(self):
        """Imprime a hierarquia de protocolos."""
        if not self.hierarchy:
            return
        print("\n" + BOLD + "=== Hierarquia de Protocolos ===" + RESET)
        total = sum(self.hierarchy.values())
        for hierarquia, count in sorted(self.hierarchy.items(), key=lambda x: -x[1]):
            pct = 100 * count / total
            print(f"  {hierarquia:<50} {count:>6}  ({pct:.1f}%)")
        print(BOLD + f"  {'TOTAL':<50} {total:>6}" + RESET)