import scapy.all as scapy
from datetime import datetime
import sys

class Captura:

    def __init__(self, interface, bpf_filter="", count=0, pcap_file=None, callback=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.callback = callback
        self.pcap_file = pcap_file
        self.packets = []
        self.running = False

    def _processarPacote (self, packet):

        packet.sniff_timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")

        packet.sniff_interface = self.interface

        if self.pcap_file:
            self.packets.append(packet)

        if self.callback:
            try:
                self.callback(packet)
            except Exception as e:
                print(f"Erro ao processar pacote: {e}")

    def iniciarCaptura(self):

        self.running = True

        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._processarPacote,
                count=self.count if self.count > 0 else 0,
                store=False
            )
        except Exception as e:
            print(f"Erro ao iniciar captura: {e}")
            sys.exit(1)
        finally:
            self.running = False
            self._salvarPcap()

    def _salvarPcap(self):
        if self.pcap_file and self.packets:
            try:
                scapy.wrpcap(self.pcap_file, self.packets)
                print(f"Pacotes salvos em {self.pcap_file}")
            except Exception as e:
                print(f"Erro ao salvar pcap: {e}")




