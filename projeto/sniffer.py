
import sys
import argparse 
from capture.capture import Captura

def parser_args():
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="Sniffer de pacotes de rede usando Scapy",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-i", "--interface",
        metavar="INTERFACE",
        help="Interface de rede para captura (ex: eth0, wlan0)"
    )

    parser.add_argument(
        "-f", "--filter",
        metavar="BPF_FILTER",
        default="",
        help="Filtro BPF para captura (ex: 'host 192.168.1.1')"
    )

    parser.add_argument(
        "-c", "--count",
        metavar="COUNT",
        type=int,
        default=0,
        help="Número de pacotes a capturar (0 para sem limite)"
    )

    return parser.parse_args()


def main():
    args = parser_args()

    if not args.interface:
        print("Erro: A interface de rede é obrigatória.")
        sys.exit(1)

    captura = Captura(
        interface=args.interface,
        bpf_filter=args.filter,
        count=args.count,
    )

    print(f"Iniciando captura na interface {args.interface}")
    captura.iniciarCaptura()

if __name__ == "__main__":
    main()



