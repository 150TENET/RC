from parsing.utils import fmt_bytes


class ConversationsTracker:
    """
    Rastreia conversas bidirecionais entre endpoints.
    Agrupa pacotes por pares de comunicação (A ↔ B).
    """

    def __init__(self, by_host=False):
        """
        Args:
            by_host (bool): Se False, usa "ip:porta"; se True, usa só "ip".
        """
        self.by_host = by_host
        self.conversations = {}  # Chave: (endpoint_a, endpoint_b, protocol)

    def _extrair_endpoints(self, parser):
        """
        Extrai os endpoints (src, dst) a partir de um parser.

        Returns:
            tuple: (src_endpoint, dst_endpoint) ou (None, None) se não puder extrair.
        """
        # Protocolos com portas (TCP, UDP, DNS)
        if hasattr(parser, 'sport') and hasattr(parser, 'dport'):
            if self.by_host:
                src = parser.src_ip
                dst = parser.dst_ip
            else:
                src = f"{parser.src_ip}:{parser.sport}" if parser.src_ip else None
                dst = f"{parser.dst_ip}:{parser.dport}" if parser.dst_ip else None
        # Protocolos sem portas (ARP, IPv4, ICMP)
        else:
            if parser.src_ip and parser.dst_ip:
                src = parser.src_ip
                dst = parser.dst_ip
            elif parser.src_mac and parser.dst_mac:
                # Fallback para MAC se não houver IP (ex: ARP)
                src = parser.src_mac.lower()
                dst = parser.dst_mac.lower()
            else:
                return None, None

        return src, dst

    def _canonizar_endpoints(self, src, dst):
        """
        Ordena endpoints alfabeticamente para criar uma chave canónica.
        Retorna (endpoint_a, endpoint_b, direcao) onde direcao é "ab" ou "ba".
        """
        if src is None or dst is None:
            return None, None, None

        if src <= dst:
            return src, dst, "ab"
        else:
            return dst, src, "ba"

    def registar(self, parser):
        """
        Regista um pacote numa conversa.

        Args:
            parser: ProtocolParser instância (com atributos protocol_name, length, etc).
        """
        src, dst = self._extrair_endpoints(parser)
        if src is None or dst is None:
            return

        endpoint_a, endpoint_b, direcao = self._canonizar_endpoints(src, dst)
        if endpoint_a is None:
            return

        chave = (endpoint_a, endpoint_b, parser.protocol_name)

        if chave not in self.conversations:
            self.conversations[chave] = {
                "pkts_ab": 0,
                "bytes_ab": 0,
                "pkts_ba": 0,
                "bytes_ba": 0,
            }

        conv = self.conversations[chave]
        if direcao == "ab":
            conv["pkts_ab"] += 1
            conv["bytes_ab"] += parser.length
        else:  # "ba"
            conv["pkts_ba"] += 1
            conv["bytes_ba"] += parser.length

    def imprimir(self, top_n=None):
        """
        Imprime uma tabela de conversas.

        Args:
            top_n (int): Se definido, mostra apenas top_n conversas por total de bytes.
        """
        if not self.conversations:
            return

        print("\n\033[1m=== Conversas " +
              ("(por host:porta)" if not self.by_host else "(por host)") +
              " ===\033[0m")

        # Ordenar por total de bytes (descendente)
        conversas_ordenadas = sorted(
            self.conversations.items(),
            key=lambda x: (x[1]["bytes_ab"] + x[1]["bytes_ba"]),
            reverse=True
        )

        if top_n:
            conversas_ordenadas = conversas_ordenadas[:top_n]

        # Cabeçalho
        cabecalho = (
            f"{'Endpoint A':<35} {'Endpoint B':<35} "
            f"{'Proto':<6} {'A->B':<18} {'B->A':<18} {'Total':<18}"
        )
        separador = "-" * len(cabecalho)
        print(cabecalho)
        print(separador)

        # Linhas
        for (endpoint_a, endpoint_b, proto), stats in conversas_ordenadas:
            pkts_ab = stats["pkts_ab"]
            bytes_ab = stats["bytes_ab"]
            pkts_ba = stats["pkts_ba"]
            bytes_ba = stats["bytes_ba"]
            total_pkts = pkts_ab + pkts_ba
            total_bytes = bytes_ab + bytes_ba

            str_ab = f"{pkts_ab}/{fmt_bytes(bytes_ab)}"
            str_ba = f"{pkts_ba}/{fmt_bytes(bytes_ba)}"
            str_total = f"{total_pkts}/{fmt_bytes(total_bytes)}"

            print(
                f"{endpoint_a:<35} {endpoint_b:<35} "
                f"{proto:<6} {str_ab:<18} {str_ba:<18} {str_total:<18}"
            )

        print(separador)
        print(f"\n  Total de conversas: {len(conversas_ordenadas)}")
