import scapy.all as scapy
from protocols.icmp import ICMP


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
            print(parser)

    def imprimirEstatisticas(self):
        if not self.stats:
            print("\nNenhum pacote capturado.")
            return
        print("\n=== Estatísticas da captura ===")
        total = sum(self.stats.values())
        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            pct = 100 * count / total
            print(f"  {proto:<6} {count:>6}  ({pct:.1f}%)")
        print(f"  {'TOTAL':<6} {total:>6}")