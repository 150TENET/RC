import scapy.all as scapy
from protocols.icmp import ICMP

# Códigos ANSI de cor por protocolo
CORES = {
    "ICMP": "\033[96m",   # ciano
    "TCP":  "\033[92m",   # verde
    "UDP":  "\033[93m",   # amarelo
    "ARP":  "\033[95m",   # magenta
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

    def __init__(self, protocol_filter=None, live=True):
        self.protocol_filter = (
            [p.upper() for p in protocol_filter] if protocol_filter else None
        )
        self.live = live
        self.stats = {}

        if self.live:
            imprimir_cabecalho()

    def identificarProtocolo(self, packet):
        """Identifica o protocolo e retorna o parser instanciado."""
        if packet.haslayer(scapy.ICMP):
            return ICMP(packet)

        return None

    def processar(self, packet):
        """Callback a ser passado ao Captura."""
        parser = self.identificarProtocolo(packet)

        if parser is None:
            return

        if self.protocol_filter and parser.protocol_name not in self.protocol_filter:
            return

        self.stats[parser.protocol_name] = self.stats.get(parser.protocol_name, 0) + 1

        if self.live:
            cor = CORES.get(parser.protocol_name, "\033[97m")
            print(cor + str(parser) + RESET)

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