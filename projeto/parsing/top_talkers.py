from collections import defaultdict
from parsing.utils import fmt_bytes


class TopTalkersTracker:
    """
    Rastreia tráfego por host individual.
    Mostra pacotes/bytes transmitidos e recebidos para cada host.
    """

    def __init__(self):
        """Inicializa o tracker de top talkers."""
        self.talkers = defaultdict(lambda: {
            "pkts_tx": 0,
            "bytes_tx": 0,
            "pkts_rx": 0,
            "bytes_rx": 0,
        })

    def _extrair_endpoint(self, src_ip, dst_ip, src_mac, dst_mac):
        """
        Extrai um endpoint a partir de IP ou MAC.

        Returns:
            str: O endpoint (IP ou MAC) ou None se não conseguir extrair.
        """
        if src_ip:
            return src_ip
        elif src_mac:
            return src_mac.lower()
        return None

    def registar(self, parser):
        """
        Regista um pacote, atualizando contadores de TX/RX para cada host.

        Args:
            parser: ProtocolParser instância com atributos src_ip, dst_ip,
                   src_mac, dst_mac, length, protocol_name.
        """
        src = self._extrair_endpoint(parser.src_ip, None, parser.src_mac, None)
        dst = self._extrair_endpoint(parser.dst_ip, None, parser.dst_mac, None)

        if src:
            self.talkers[src]["pkts_tx"] += 1
            self.talkers[src]["bytes_tx"] += parser.length

        if dst:
            self.talkers[dst]["pkts_rx"] += 1
            self.talkers[dst]["bytes_rx"] += parser.length

    def imprimir(self, top_n=10, sort_by="bytes_total"):
        """
        Imprime uma tabela de top talkers.

        Args:
            top_n (int): Número máximo de hosts a mostrar (default 10).
            sort_by (str): Critério de ordenação:
                         "bytes_total", "bytes_tx", "bytes_rx",
                         "pkts_total", "pkts_tx", "pkts_rx" (default: "bytes_total").
        """
        if not self.talkers:
            return

        # Preparar dados com totais
        talkers_data = []
        for host, stats in self.talkers.items():
            pkts_total = stats["pkts_tx"] + stats["pkts_rx"]
            bytes_total = stats["bytes_tx"] + stats["bytes_rx"]
            talkers_data.append({
                "host": host,
                "pkts_tx": stats["pkts_tx"],
                "pkts_rx": stats["pkts_rx"],
                "pkts_total": pkts_total,
                "bytes_tx": stats["bytes_tx"],
                "bytes_rx": stats["bytes_rx"],
                "bytes_total": bytes_total,
            })

        # Ordenar pelo critério especificado
        sort_key_map = {
            "bytes_total": lambda x: x["bytes_total"],
            "bytes_tx": lambda x: x["bytes_tx"],
            "bytes_rx": lambda x: x["bytes_rx"],
            "pkts_total": lambda x: x["pkts_total"],
            "pkts_tx": lambda x: x["pkts_tx"],
            "pkts_rx": lambda x: x["pkts_rx"],
        }
        sort_key = sort_key_map.get(sort_by, sort_key_map["bytes_total"])
        talkers_data.sort(key=sort_key, reverse=True)

        # Limitar a top_n
        if top_n:
            talkers_data = talkers_data[:top_n]

        # Cabeçalho
        print("\n\033[1m=== Top Talkers (por " + sort_by + ") ===\033[0m")

        cabecalho = (
            f"{'Host':<35} {'Pkts TX':<11} {'Pkts RX':<11} "
            f"{'Bytes TX':<14} {'Bytes RX':<14} {'Total':<14}"
        )
        separador = "-" * len(cabecalho)
        print(cabecalho)
        print(separador)

        # Linhas
        for data in talkers_data:
            host = data["host"]
            pkts_tx = data["pkts_tx"]
            pkts_rx = data["pkts_rx"]
            bytes_tx = fmt_bytes(data["bytes_tx"])
            bytes_rx = fmt_bytes(data["bytes_rx"])
            total = fmt_bytes(data["bytes_total"])

            print(
                f"{host:<35} {pkts_tx:<11} {pkts_rx:<11} "
                f"{bytes_tx:<14} {bytes_rx:<14} {total:<14}"
            )

        print(separador)
        print(f"\n  Total de hosts: {len(talkers_data)}")
