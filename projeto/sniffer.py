from html import parser
import sys
import argparse
from capture.capture import Captura
from parsing.dispatcher import Dispatcher 
from parsing.logger import Logger

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

    return parser.parse_args()


def main():
    args = parser_args()

    # Criar logger se o utilizador pediu
    logger = None
    if args.log:
        logger = Logger(args.log, formato=args.log_format)
    
    dispatcher = Dispatcher(
        protocol_filter=args.protocol,
        ip_filter=args.ip,
        mac_filter=args.mac,
        live=not args.no_live,
        logger=logger, 
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
    print("[] Ctrl+C para parar\n")

    try:
        captura.iniciarCaptura()
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo utilizador.")

    dispatcher.imprimirEstatisticas()

    if logger:
        logger.fim()
        print(f"\nLog guardado em: {args.log}")


if __name__ == "__main__":
    main()

