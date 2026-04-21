import sys
import argparse
from capture.capture import Captura
from parsing.dispatcher import Dispatcher 


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

    parser.add_argument("-w", "--write", default=None,
                        metavar="FILE.pcap",
                        help="Guardar captura num ficheiro .pcap")

    parser.add_argument("--no-live", action="store_true",
                        help="Não imprimir pacotes em tempo real")

    return parser.parse_args()


def main():
    args = parser_args()

    dispatcher = Dispatcher(
        protocol_filter=args.protocol,
        live=not args.no_live,
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
        print("\n[*] Captura interrompida pelo utilizador.")

    dispatcher.imprimirEstatisticas()


if __name__ == "__main__":
    main()

