import scapy.all as scapy
from datetime import datetime
import sys
import threading
import time

class Captura:

    def __init__(self, interface, bpf_filter="", count=0, pcap_file=None, callback=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.callback = callback
        self.pcap_file = pcap_file
        self.packets = []
        self.running = False
        self.paused = False
        self.stopped = False
        self.capture_thread = None
        self.packets_captured = 0
        self.paused_lock = threading.Lock()
        self.pause_event = threading.Event()
        self.pause_event.set()

    def _processarPacote(self, packet):
        self.pause_event.wait()

        packet.sniff_timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")
        packet.sniff_interface = self.interface

        if self.pcap_file:
            self.packets.append(packet)

        if self.callback:
            try:
                self.callback(packet)
            except Exception as e:
                print(f"Erro ao processar pacote: {e}")

        self.packets_captured += 1

    def _capturar(self):
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._processarPacote,
                count=self.count if self.count > 0 else 0,
                store=False,
                stop_filter=lambda pkt: self.stopped
            )
        except Exception as e:
            print(f"Erro ao iniciar captura: {e}")
            sys.exit(1)
        finally:
            self.running = False
            self._salvarPcap()

    def iniciarCaptura(self):
        self.running = True
        self.stopped = False
        self.paused = False
        self.packets_captured = 0
        self.pause_event.set()
        self.capture_thread = threading.Thread(target=self._capturar, daemon=False)
        self.capture_thread.start()

    def pausarCaptura(self):
        if self.running and not self.paused:
            with self.paused_lock:
                self.paused = True
                self.pause_event.clear()
            print("\n[PAUSADO] Captura parada. Digite 'r' para retomar, 'q' para sair.")

    def retomarCaptura(self):
        if self.running and self.paused:
            with self.paused_lock:
                self.paused = False
                self.pause_event.set()
            print("[RETOMADO] Captura em progresso...")

    def pararCaptura(self):
        self.stopped = True
        self.running = False
        self.pause_event.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)

    def _salvarPcap(self):
        if self.pcap_file and self.packets:
            try:
                scapy.wrpcap(self.pcap_file, self.packets)
                print(f"\nPacotes salvos em {self.pcap_file}")
            except Exception as e:
                print(f"Erro ao salvar pcap: {e}")




