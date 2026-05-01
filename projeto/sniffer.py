import sys
import argparse
import threading
import time
from capture.capture import Captura
from parsing.dispatcher import Dispatcher
from parsing.logger import Logger
from parsing.conversations import ConversationsTracker
from parsing.top_talkers import TopTalkersTracker
from parsing.follow_stream import TCPStreamTracker

def parser_args():
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="Sniffer de pacotes de rede (Scapy)",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-i", "--interface", required=True,
                        metavar="INTERFACE",
                        help="Interface de rede para captura (ex: eth0, wlan0)")

    parser.add_argument("-f", "--filter", default="",
                        metavar="BPF_FILTER",
                        help="Filtro BPF (ex: 'host 192.168.1.1', 'icmp')")

    parser.add_argument("-c", "--count", type=int, default=0,
                        metavar="N",
                        help="Número de pacotes a capturar (0 = ilimitado)")

    parser.add_argument("-p", "--protocol", action="append",
                        metavar="PROTO",
                        help="Filtrar por protocolo (repetível). Ex: -p ICMP -p ARP")

    parser.add_argument("--ip", default=None,
                        metavar="IP",
                        help="Filtrar por endereço IP (origem ou destino). Ex: --ip 192.168.1.1")

    parser.add_argument("--mac", default=None,
                        metavar="MAC",
                        help="Filtrar por endereço MAC (origem ou destino). Ex: --mac aa:bb:cc:dd:ee:ff")

    parser.add_argument("-w", "--write", default=None,
                        metavar="FILE.pcap",
                        help="Guardar captura num ficheiro .pcap")

    parser.add_argument("--no-live", action="store_true",
                        help="Não imprimir pacotes em tempo real")

    parser.add_argument("-l", "--log", default=None,
                        metavar="FILE",
                        help="Ficheiro para guardar log do tráfego (txt/csv/json)")

    parser.add_argument("--log-format", default="txt",
                        choices=["txt", "csv", "json"],
                        help="Formato do ficheiro de log (default: txt)")

    parser.add_argument("--no-fragments", action="store_true",
                        help="Rejeitar pacotes fragmentados")

    parser.add_argument("--only-fragments", action="store_true",
                        help="Capturar apenas pacotes fragmentados")

    parser.add_argument("--frag-id", type=int, default=None,
                        metavar="ID",
                        help="Filtrar por ID de fragmento")

    parser.add_argument("--frag-offset", type=int, default=None,
                        metavar="BYTES",
                        help="Filtrar por offset de fragmento (em bytes)")

    parser.add_argument("--first-fragment", action="store_true",
                        help="Capturar apenas primeiro fragmento (offset=0, MF=1)")

    parser.add_argument("--last-fragment", action="store_true",
                        help="Capturar apenas último fragmento (MF=0, offset>0)")

    # Análise pós-captura
    analysis_group = parser.add_argument_group("análise pós-captura")
    analysis_group.add_argument("--conversations", action="store_true",
                               help="Mostrar conversas entre endpoints")

    analysis_group.add_argument("--conversations-by-host", action="store_true",
                               help="Agrupar conversas por host (sem portas)")

    analysis_group.add_argument("--conversations-top", type=int, default=None,
                               metavar="N",
                               help="Mostrar apenas top N conversas por total de bytes")

    analysis_group.add_argument("--top-talkers", action="store_true",
                               help="Mostrar top talkers (hosts com mais tráfego)")

    analysis_group.add_argument("--top-talkers-n", type=int, default=10,
                               metavar="N",
                               help="Número de top talkers a mostrar (default: 10)")

    analysis_group.add_argument("--top-talkers-sort",
                               choices=["bytes_total", "bytes_tx", "bytes_rx",
                                       "pkts_total", "pkts_tx", "pkts_rx"],
                               default="bytes_total",
                               help="Critério de ordenação (default: bytes_total)")

    analysis_group.add_argument("--list-streams", action="store_true",
                               help="Listar todas as sessões TCP detetadas")

    analysis_group.add_argument("--follow-stream", type=int, default=None,
                               metavar="N",
                               help="Mostrar detalhe completo da sessão TCP #N")

    return parser.parse_args()


def input_thread(captura):
    """
    Thread que escuta comandos do utilizador (p/r/q).
    Usa select para não bloquear indefinidamente em input(), de modo
    a poder verificar periodicamente se a captura terminou.
    """
    import select
    while captura.running:
        # Espera até 0.5s por input no stdin
        rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
        if not rlist:
            continue  # nada para ler, volta a verificar captura.running

        try:
            cmd = sys.stdin.readline().strip().lower()
            if not cmd:
                continue
            if cmd == 'p':
                captura.pausarCaptura()
            elif cmd == 'r':
                captura.retomarCaptura()
            elif cmd == 'q':
                captura.pararCaptura()
                break
        except EOFError:
            break
        except Exception as e:
            print(f"Erro ao processar comando: {e}")


def main():
    args = parser_args()

    # Criar logger se o utilizador pediu
    logger = None
    if args.log:
        logger = Logger(args.log, formato=args.log_format)

    # Construir filtros de fragmentação
    frag_filter = {}
    if args.no_fragments:
        frag_filter["no_fragments"] = True
    if args.only_fragments:
        frag_filter["only_fragments"] = True
    if args.frag_id is not None:
        frag_filter["frag_id"] = args.frag_id
    if args.frag_offset is not None:
        frag_filter["frag_offset"] = args.frag_offset
    if args.first_fragment:
        frag_filter["first_fragment"] = True
    if args.last_fragment:
        frag_filter["last_fragment"] = True

    # Instanciar trackers de análise pós-captura
    conv_tracker = None
    if args.conversations or args.conversations_by_host:
        conv_tracker = ConversationsTracker(by_host=args.conversations_by_host)

    talkers_tracker = None
    if args.top_talkers:
        talkers_tracker = TopTalkersTracker()

    stream_tracker = None
    if args.list_streams or args.follow_stream is not None:
        stream_tracker = TCPStreamTracker()

    dispatcher = Dispatcher(
        protocol_filter=args.protocol,
        ip_filter=args.ip,
        mac_filter=args.mac,
        frag_filter=frag_filter,
        live=not args.no_live,
        logger=logger,
        conv_tracker=conv_tracker,
        talkers_tracker=talkers_tracker,
        stream_tracker=stream_tracker,
    )

    captura = Captura(
        interface=args.interface,
        bpf_filter=args.filter,
        count=args.count,
        pcap_file=args.write,
        callback=dispatcher.processar,
    )

    print(f"[] A capturar em {args.interface}"
          f"{' (filtro BPF: ' + args.filter + ')' if args.filter else ''}")
    print("[] Comandos: (p)ausar, (r)etomar, (q)uit")
    print("[] Ctrl+C para parar\n")

    cmd_thread = None
    try:
        captura.iniciarCaptura()

        cmd_thread = threading.Thread(target=input_thread, args=(captura,), daemon=True)
        cmd_thread.start()

        # Aguardar até a captura terminar
        while captura.running:
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo utilizador.")
        captura.pararCaptura()

    # Esperar pela thread de input terminar (até 1s)
    if cmd_thread is not None and cmd_thread.is_alive():
        cmd_thread.join(timeout=1)

    dispatcher.imprimirEstatisticas()
    dispatcher.imprimirHierarquia()

    if conv_tracker:
        conv_tracker.imprimir(top_n=args.conversations_top)

    if talkers_tracker:
        talkers_tracker.imprimir(top_n=args.top_talkers_n, sort_by=args.top_talkers_sort)

    if stream_tracker:
        if args.list_streams:
            stream_tracker.listar_sessoes()
        if args.follow_stream is not None:
            stream_tracker.mostrar_sessao(args.follow_stream)

    if logger:
        logger.fim()
        print(f"\nLog guardado em: {args.log}")


if __name__ == "__main__":
    main()

