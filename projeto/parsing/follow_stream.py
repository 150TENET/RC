from datetime import datetime
from parsing.utils import fmt_bytes


class TCPStreamTracker:
    """
    Rastreia sessões TCP (4-tuplo), reconstrói sequências de pacotes,
    deteta retransmissões e mantém estado da máquina TCP.
    """

    def __init__(self):
        """Inicializa o tracker de streams TCP."""
        self.streams = {}  # Chave: (endpoint_a, endpoint_b), valor: dict stream
        self.next_stream_id = 1

    def _extrair_flags_str(self, parser):
        """Extrai string de flags TCP (ex: 'SYN', 'SYN+ACK', 'PSH+ACK')."""
        if not hasattr(parser, 'flags'):
            return ""
        flags = []
        if hasattr(parser, 'is_syn') and parser.is_syn:
            flags.append("SYN")
        if hasattr(parser, 'is_ack') and parser.is_ack:
            flags.append("ACK")
        if hasattr(parser, 'is_fin') and parser.is_fin:
            flags.append("FIN")
        if hasattr(parser, 'is_rst') and parser.is_rst:
            flags.append("RST")
        if hasattr(parser, 'is_psh') and parser.is_psh:
            flags.append("PSH")
        return "+".join(flags) if flags else ""

    def _canonizar_endpoints(self, src, dst):
        """
        Ordena endpoints (ip:porta) alfabeticamente.
        Retorna (endpoint_a, endpoint_b, direcao) onde direcao é "a_to_b" ou "b_to_a".
        """
        if src <= dst:
            return src, dst, "a_to_b"
        else:
            return dst, src, "b_to_a"

    def _atualizar_estado(self, stream, flags_str, direction):
        """
        Atualiza o estado da máquina TCP baseado nas flags.
        Máquina de estados simplificada.
        """
        state = stream["state"]

        # RST em qualquer estado → RESET
        if "RST" in flags_str:
            stream["state"] = "RESET"
            return

        # SYN sozinho (primeiro pacote do handshake)
        if flags_str == "SYN":
            if state == "CLOSED" or state is None:
                stream["state"] = "SYN_SENT"

        # SYN+ACK (segundo pacote do handshake)
        elif flags_str == "SYN+ACK":
            if state == "SYN_SENT":
                stream["state"] = "SYN_ACK_RECEIVED"

        # ACK puro depois do SYN+ACK (terceiro pacote do handshake)
        elif flags_str == "ACK" and state == "SYN_ACK_RECEIVED":
            stream["state"] = "ESTABLISHED"

        # ACK puro em ESTABLISHED (continua em ESTABLISHED)
        elif flags_str == "ACK" and state == "ESTABLISHED":
            pass

        # PSH+ACK em ESTABLISHED
        elif "PSH" in flags_str and state == "ESTABLISHED":
            pass

        # FIN em ESTABLISHED → FIN_SENT
        elif "FIN" in flags_str and state == "ESTABLISHED":
            stream["state"] = "FIN_SENT"

        # FIN em FIN_SENT → CLOSING (segundo FIN)
        elif "FIN" in flags_str and state == "FIN_SENT":
            stream["state"] = "CLOSING"

        # ACK em CLOSING → CLOSED
        elif flags_str == "ACK" and state == "CLOSING":
            stream["state"] = "CLOSED"

        # FIN+ACK pode também ser usado no closing
        elif "FIN" in flags_str and "ACK" in flags_str:
            if state == "ESTABLISHED":
                stream["state"] = "FIN_SENT"
            elif state == "FIN_SENT":
                stream["state"] = "CLOSING"

    def registar(self, parser):
        """
        Regista um pacote TCP numa sessão.

        Args:
            parser: ProtocolParser instância com protocol_name="TCP" e atributos
                   src_ip, dst_ip, sport, dport, length, seq, ack, flags, etc.
        """
        # Apenas processa pacotes TCP
        if not hasattr(parser, 'protocol_name') or parser.protocol_name != "TCP":
            return

        # Extrair 4-tuplo
        if not (hasattr(parser, 'src_ip') and hasattr(parser, 'dst_ip') and
                hasattr(parser, 'sport') and hasattr(parser, 'dport')):
            return

        src_endpoint = f"{parser.src_ip}:{parser.sport}"
        dst_endpoint = f"{parser.dst_ip}:{parser.dport}"

        # Canonizar para ter sempre o mesmo par na mesma chave
        endpoint_a, endpoint_b, direction = self._canonizar_endpoints(src_endpoint, dst_endpoint)
        stream_key = (endpoint_a, endpoint_b)

        # Criar stream se não existir
        if stream_key not in self.streams:
            self.streams[stream_key] = {
                "id": self.next_stream_id,
                "endpoint_a": endpoint_a,
                "endpoint_b": endpoint_b,
                "state": None,  # Será atualizado no primeiro pacote
                "packets": [],
                "pkts_total": 0,
                "bytes_a_to_b": 0,
                "bytes_b_to_a": 0,
                "retransmissions": 0,
                "first_timestamp": None,
                "last_timestamp": None,
                "seen_seqs": {"a_to_b": set(), "b_to_a": set()},  # Para detetar retransmissões
            }
            self.next_stream_id += 1

        stream = self.streams[stream_key]

        # Extrair informações do pacote
        flags_str = self._extrair_flags_str(parser)
        seq = getattr(parser, 'seq', 0)
        ack = getattr(parser, 'ack', 0)
        length = getattr(parser, 'length', 0)
        timestamp = getattr(parser, 'sniff_timestamp', datetime.now())

        # Detetar retransmissão
        is_retransmission = False
        if seq in stream["seen_seqs"][direction]:
            is_retransmission = True
            stream["retransmissions"] += 1
        else:
            stream["seen_seqs"][direction].add(seq)

        # Atualizar estado da máquina TCP
        self._atualizar_estado(stream, flags_str, direction)

        # Adicionar pacote
        packet_info = {
            "timestamp": timestamp,
            "direction": direction,
            "flags_str": flags_str,
            "seq": seq,
            "ack": ack,
            "length": length,
            "is_retransmission": is_retransmission,
        }
        stream["packets"].append(packet_info)

        # Atualizar contadores
        stream["pkts_total"] += 1
        if direction == "a_to_b":
            stream["bytes_a_to_b"] += length
        else:
            stream["bytes_b_to_a"] += length

        # Atualizar timestamps
        if stream["first_timestamp"] is None:
            stream["first_timestamp"] = timestamp
        stream["last_timestamp"] = timestamp

    def listar_sessoes(self):
        """Imprime tabela resumo de todas as sessões TCP."""
        if not self.streams:
            print("\nNenhuma sessão TCP detetada.")
            return

        print("\n\033[1m=== Sessões TCP detetadas ===\033[0m")

        cabecalho = (
            f"{'ID':<4} {'Endpoint A':<30} {'Endpoint B':<30} "
            f"{'Estado':<15} {'Pkts':<7} {'Dados':<12} {'RTX':<3}"
        )
        separador = "-" * len(cabecalho)
        print(cabecalho)
        print(separador)

        # Ordenar por id
        sessoes_ordenadas = sorted(self.streams.values(), key=lambda x: x["id"])

        for stream in sessoes_ordenadas:
            stream_id = stream["id"]
            endpoint_a = stream["endpoint_a"][:30]
            endpoint_b = stream["endpoint_b"][:30]
            state = stream["state"] or "CLOSED"
            pkts = stream["pkts_total"]
            total_bytes = stream["bytes_a_to_b"] + stream["bytes_b_to_a"]
            bytes_str = fmt_bytes(total_bytes)
            rtx = stream["retransmissions"]

            print(
                f"{stream_id:<4} {endpoint_a:<30} {endpoint_b:<30} "
                f"{state:<15} {pkts:<7} {bytes_str:<12} {rtx:<3}"
            )

        print(separador)
        print(f"\n  Total de sessões: {len(sessoes_ordenadas)}")

    def mostrar_sessao(self, stream_id):
        """
        Imprime detalhe completo da sessão TCP com o id dado.

        Args:
            stream_id (int): O id da sessão a mostrar.
        """
        # Encontrar stream
        stream = None
        for s in self.streams.values():
            if s["id"] == stream_id:
                stream = s
                break

        if not stream:
            print(f"\nErro: Sessão #{stream_id} não encontrada.")
            return

        # Cabeçalho
        print(f"\n\033[1m=== Sessão #{stream_id}: {stream['endpoint_a']} ↔ {stream['endpoint_b']} ===\033[0m")

        if not stream["packets"]:
            print("Nenhum pacote registado nesta sessão.")
            return

        # Tabela de pacotes
        cabecalho = (
            f"{'#':<4} {'Tempo':<10} {'Direção':<9} {'Flags':<15} "
            f"{'Seq':<12} {'Ack':<12} {'Len':<7} {'Notas':<30}"
        )
        separador = "-" * len(cabecalho)
        print(cabecalho)
        print(separador)

        first_timestamp = stream["first_timestamp"]
        is_syn_received = False
        is_syn_ack_received = False
        is_ack_received = False

        for idx, packet in enumerate(stream["packets"], start=1):
            # Tempo relativo
            if isinstance(first_timestamp, str):
                # Se for string, usamos offset simples
                time_offset = f"+{idx * 0.001:.3f}s"
            else:
                # Se for datetime
                try:
                    delta = packet["timestamp"] - first_timestamp
                    time_offset = f"+{delta.total_seconds():.3f}s"
                except:
                    time_offset = f"+{idx * 0.001:.3f}s"

            # Direção com setas
            direction_str = "→" if packet["direction"] == "a_to_b" else "←"

            flags = packet["flags_str"]
            seq = packet["seq"]
            ack = packet["ack"]
            length = packet["length"]

            # Notas
            notes = []
            if packet["is_retransmission"]:
                notes.append("RETRANSMISSION")

            # Detetar handshake
            if flags == "SYN" and not is_syn_received:
                notes.append("handshake 1/3")
                is_syn_received = True
            elif flags == "SYN+ACK" and is_syn_received and not is_syn_ack_received:
                notes.append("handshake 2/3")
                is_syn_ack_received = True
            elif flags == "ACK" and is_syn_ack_received and not is_ack_received:
                notes.append("handshake 3/3")
                is_ack_received = True

            # Data
            if length > 0:
                notes.append(f"[data {length}B]")

            # FIN/RST
            if "FIN" in flags:
                notes.append("FIN")
            if "RST" in flags:
                notes.append("RST")

            notes_str = ", ".join(notes) if notes else ""

            print(
                f"{idx:<4} {time_offset:<10} {direction_str:<9} {flags:<15} "
                f"{seq:<12} {ack:<12} {length:<7} {notes_str:<30}"
            )

        print(separador)

        # Resumo
        total_bytes = stream["bytes_a_to_b"] + stream["bytes_b_to_a"]
        state = stream["state"] or "CLOSED"
        print(f"\nResumo: {fmt_bytes(stream['bytes_a_to_b'])} a→b, "
              f"{fmt_bytes(stream['bytes_b_to_a'])} b→a, "
              f"{stream['retransmissions']} retransmissões, estado={state}")
