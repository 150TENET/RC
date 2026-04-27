import json
import csv
from datetime import datetime


class Logger:
    """
    Escreve cada pacote num ficheiro de log no formato escolhido.
    Suporta três formatos: txt, csv, json.
    O ficheiro é aberto no construtor e fechado em fim().
    """

    FORMATOS_VALIDOS = {"txt", "csv", "json"}

    def __init__(self, ficheiro, formato="txt"):
        if formato not in self.FORMATOS_VALIDOS:
            raise ValueError(
                f"Formato '{formato}' inválido. Use: {self.FORMATOS_VALIDOS}"
            )

        self.ficheiro = ficheiro
        self.formato = formato
        self.fp = open(ficheiro, "w", encoding="utf-8", newline="")
        self.csv_writer = None
        self.json_first = True

        self._escrever_cabecalho()

    def _escrever_cabecalho(self):
        if self.formato == "txt":
            self.fp.write(f"# Sniffer log iniciado em {datetime.now().isoformat()}\n")
            self.fp.write(f"# Formato: timestamp | iface | proto | size | detalhe\n\n")

        elif self.formato == "csv":
            self.csv_writer = csv.writer(self.fp)
            self.csv_writer.writerow([
                "timestamp", "interface", "protocol", "length",
                "src_mac", "dst_mac", "src_ip", "dst_ip", "summary"
            ])

        elif self.formato == "json":
            # Inicia uma lista JSON, cada pacote será um objeto
            self.fp.write("[\n")

    def registar(self, parser):
        """Registar um pacote (recebe um objeto ProtocolParser)."""
        if self.formato == "txt":
            self.fp.write(str(parser) + "\n")

        elif self.formato == "csv":
            self.csv_writer.writerow([
                parser.timestamp,
                parser.interface,
                parser.protocol_name,
                parser.length,
                parser.src_mac or "",
                parser.dst_mac or "",
                parser.src_ip or "",
                parser.dst_ip or "",
                parser.summary(),
            ])

        elif self.formato == "json":
            obj = {
                "timestamp": parser.timestamp,
                "interface": parser.interface,
                "protocol": parser.protocol_name,
                "length": parser.length,
                "src_mac": parser.src_mac,
                "dst_mac": parser.dst_mac,
                "src_ip": parser.src_ip,
                "dst_ip": parser.dst_ip,
                "summary": parser.summary(),
            }
            # Vírgula entre objetos, exceto antes do primeiro
            if not self.json_first:
                self.fp.write(",\n")
            self.json_first = False
            self.fp.write("  " + json.dumps(obj, ensure_ascii=False))

        # Flush periódico para não perder dados se o programa crashar
        self.fp.flush()

    def fim(self):
        """Fecha o ficheiro. Chamar no fim da captura."""
        if self.formato == "json":
            self.fp.write("\n]\n")
        self.fp.close()